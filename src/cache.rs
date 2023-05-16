// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::error::Error;
use canonical::EncodeToVec;

use std::cmp::Ordering;
use std::collections::BTreeSet;

use std::path::Path;

use canonical::{Canon, Source};
use canonical_derive::Canon;
use dusk_bytes::Serializable;
use dusk_pki::{PublicSpendKey, SecretSpendKey};
use phoenix_core::Note;
use rocksdb::{ColumnFamily, Options, WriteBatch, DB};

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
    pub(crate) fn new<T: AsRef<Path>>(path: T) -> Result<Self, Error> {
        let db: DB;
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        // After 10 million bytes, sort the cache file and create new one
        opts.set_write_buffer_size(10_000_000);

        let list = DB::list_cf(&Options::default(), &path);

        if list.is_err() {
            db = DB::open(&opts, path)?;
        } else {
            db = DB::open_cf(&opts, path, list?)?;
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
        psk: PublicSpendKey,
        sk: &SecretSpendKey,
        height: u64,
        note: Note,
    ) -> Result<(), Error> {
        let cf: &ColumnFamily;
        let cf_name = format!("{:?}", psk);
        let key = note.gen_nullifier(sk).to_bytes();
        let mut data = KeyData {
            last_height: height,
            notes: BTreeSet::new(),
        };

        if let Some(column_family) = self.db.cf_handle(&cf_name) {
            cf = column_family;

            if let Some(data_bytes) = self.db.get_cf(cf, &key)? {
                let mut source = Source::new(&data_bytes);
                data = KeyData::decode(&mut source)?;
            }
        } else {
            // immediately create a cf by the hex of the psk_bytes
            self.db.create_cf(&cf_name, &Options::default())?;

            cf = self
                .db
                .cf_handle(&cf_name)
                .expect("cannot create column family for db");
        }

        data.notes.insert(NoteData { height, note });

        let value = data.encode_to_vec();

        self.write_batch.put_cf(cf, key, value);

        Ok(())
    }

    pub(crate) fn persist(&self) -> Result<(), Error> {
        self.db
            .write(WriteBatch::from_data(self.write_batch.data()))?;

        Ok(())
    }

    /// Returns the block height of the highest ever note inserted for the given
    /// PSK. If no note has ever been inserted it returns 0.
    pub(crate) fn last_height(
        &self,
        psk: PublicSpendKey,
    ) -> Result<u64, Error> {
        let cf_name = format!("{:?}", psk);

        if let Some(cf) = self.db.cf_handle(&cf_name) {
            let iterator =
                self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

            if let Some(last) = iterator.last() {
                let (_, data) = last?;
                let data = KeyData::decode(&mut Source::new(&data))?;

                return Ok(data.last_height);
            }
        };

        Ok(0)
    }

    /// Returns an iterator over all notes inserted for the given PSK, in order
    /// of block height.
    pub(crate) fn notes(
        &self,
        psk: PublicSpendKey,
    ) -> Result<BTreeSet<NoteData>, Error> {
        let cf_name = format!("{:?}", psk);
        let mut notes = BTreeSet::<NoteData>::new();

        if let Some(cf) = self.db.cf_handle(&cf_name) {
            let iterator =
                self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

            for i in iterator {
                let (_, data) = i?;
                let mut source = Source::new(&data);
                let data = KeyData::decode(&mut source)?;

                notes.extend(data.notes);
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

#[derive(Debug, Clone, Canon)]
struct KeyData {
    last_height: u64,
    notes: BTreeSet<NoteData>,
}
