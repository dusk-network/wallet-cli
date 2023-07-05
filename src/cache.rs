// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::path::Path;

use canonical::{Canon, EncodeToVec, Source};
use canonical_derive::Canon;
use dusk_bytes::Serializable;
use dusk_jubjub::BlsScalar;
use dusk_pki::PublicSpendKey;
use dusk_wallet_core::Store;
use phoenix_core::Note;
use rocksdb::{Options, WriteBatch, DB};

use crate::{error::Error, store::LocalStore, MAX_ADDRESSES};

/// A cache of notes received from Rusk.
///
/// path is the path of the rocks db database
pub(crate) struct Cache {
    db: DB,
    // Persist writes atomically
    write_batch: WriteBatch,
}

impl Cache {
    /// Returns a new cache instance.
    pub(crate) fn new<T: AsRef<Path>>(
        path: T,
        store: &LocalStore,
    ) -> Result<Self, Error> {
        let mut db: DB;
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        // After 10 million bytes, sort the cache file and create new one
        opts.set_write_buffer_size(10_000_000);

        let list = DB::list_cf(&Options::default(), &path);

        if let Ok(list) = list {
            db = DB::open_cf(&opts, path, list)?;
        } else {
            db = DB::open(&opts, path)?;

            // create all CF(s) on startup if we don't have them
            for i in 0..MAX_ADDRESSES {
                let ssk = store.retrieve_ssk(i as u64)?;
                let psk = ssk.view_key().public_spend_key();

                db.create_cf(&format!("{:?}", psk), &Options::default())?;
            }
        }
        let write_batch = WriteBatch::default();

        Ok(Self { db, write_batch })
    }

    // We store a column family named by hex representation of the psk.
    // We store key as (psk, note) and value as (KeyData)
    // The Canon of the tuple, we use it so we can have unique keys per psk and
    // note
    pub(crate) fn insert(
        &mut self,
        psk: &PublicSpendKey,
        height: u64,
        note_data: (Note, BlsScalar),
    ) -> Result<(), Error> {
        let cf_name = format!("{:?}", psk);

        let cf = self
            .db
            .cf_handle(&cf_name)
            .ok_or(Error::CacheDatabaseCorrupted)?;

        let (note, nullifier) = note_data;

        let data = NoteData { height, note };
        let key = nullifier.to_bytes();

        self.write_batch.put_cf(cf, key, data.encode_to_vec());

        Ok(())
    }

    pub(crate) fn persist(&mut self, last_height: u64) -> Result<(), Error> {
        self.db.put(b"last_height", last_height.to_be_bytes())?;

        self.db
            .write(WriteBatch::from_data(self.write_batch.data()))?;

        self.write_batch.clear();

        Ok(())
    }

    /// Returns the global block height inserted. If no note has ever been
    /// inserted it returns 0.
    pub(crate) fn last_height(&self) -> Result<u64, Error> {
        if let Some(x) = self.db.get(b"last_height")? {
            let buff: [u8; 8] = x.try_into().expect("Invalid u64 in cache db");

            return Ok(u64::from_be_bytes(buff));
        }

        Ok(0)
    }

    /// Returns an iterator over all notes inserted for the given PSK, in order
    /// of block height.
    pub(crate) fn notes(
        &self,
        psk: &PublicSpendKey,
    ) -> Result<BTreeSet<NoteData>, Error> {
        let cf_name = format!("{:?}", psk);
        let mut notes = BTreeSet::<NoteData>::new();

        if let Some(cf) = self.db.cf_handle(&cf_name) {
            let iterator =
                self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

            for i in iterator {
                let (_, note_data) = i?;

                let mut source = Source::new(&note_data);
                let note = NoteData::decode(&mut source)?;

                notes.insert(note);
            }
        };

        Ok(notes)
    }
}

/// Data kept about each note.
#[derive(Debug, Clone, PartialEq, Eq, Canon)]
pub(crate) struct NoteData {
    pub height: u64,
    pub note: Note,
}

impl PartialOrd for NoteData {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NoteData {
    fn cmp(&self, other: &Self) -> Ordering {
        self.note.pos().cmp(other.note.pos())
    }
}
