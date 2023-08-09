// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::path::Path;

use dusk_bytes::{DeserializableSlice, Serializable};
use dusk_pki::PublicSpendKey;
use dusk_plonk::prelude::BlsScalar;
use dusk_wallet_core::Store;
use phoenix_core::Note;
use rocksdb::{DBWithThreadMode, MultiThreaded, Options};

use crate::{error::Error, store::LocalStore, MAX_ADDRESSES};

type DB = DBWithThreadMode<MultiThreaded>;

/// A cache of notes received from Rusk.
///
/// path is the path of the rocks db database
pub(crate) struct Cache {
    db: DB,
}

impl Cache {
    /// Returns a new cache instance.
    pub(crate) fn new<T: AsRef<Path>>(
        path: T,
        store: &LocalStore,
    ) -> Result<Self, Error> {
        let cfs: Vec<_> = (0..MAX_ADDRESSES)
            .map(|i| {
                let ssk =
                    store.retrieve_ssk(i as u64).expect("ssk to be available");
                let psk = ssk.public_spend_key();
                format!("{:?}", psk)
            })
            .collect();

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        // After 10 million bytes, sort the cache file and create new one
        opts.set_write_buffer_size(10_000_000);

        // create all CF(s) on startup if we don't have them
        let db = DB::open_cf(&opts, path, cfs)?;

        Ok(Self { db })
    }

    // We store a column family named by hex representation of the psk.
    // We store the nullifier of the note as key and the value is the bytes
    // representation of the tuple (NoteHeight, Note)
    pub(crate) fn insert(
        &self,
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

        self.db.put_cf(&cf, key, data.to_bytes())?;

        Ok(())
    }

    pub(crate) fn insert_last_height(
        &self,
        last_height: u64,
    ) -> Result<(), Error> {
        self.db.put(b"last_height", last_height.to_be_bytes())?;

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
                self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);

            for i in iterator {
                let (_, note_data) = i?;

                let note = NoteData::from_slice(&note_data)?;

                notes.insert(note);
            }
        };

        Ok(notes)
    }
}

/// Data kept about each note.
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl Serializable<{ u64::SIZE + Note::SIZE }> for NoteData {
    type Error = dusk_bytes::Error;
    /// Converts a Note into a byte representation

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];

        buf[0..8].copy_from_slice(&self.height.to_bytes());

        buf[8..].copy_from_slice(&self.note.to_bytes());

        buf
    }

    /// Attempts to convert a byte representation of a note into a `Note`,
    /// failing if the input is invalid
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut one_u64 = [0u8; 8];
        one_u64.copy_from_slice(&bytes[0..8]);
        let height = u64::from_bytes(&one_u64)?;

        let note = Note::from_slice(&bytes[8..])?;
        Ok(Self { height, note })
    }
}
