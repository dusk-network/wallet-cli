// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::error::Error;

use canonical::{Canon, EncodeToVec, Source};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::path::Path;

use canonical_derive::Canon;

use dusk_pki::PublicSpendKey;

use phoenix_core::Note;
use rocksdb::{Options, WriteBatch, DB};

/// A cache of notes received from Rusk.
///
/// path is the path of the rocks db database
pub(crate) struct Cache {
    db: DB,
    write_batch: WriteBatch,
}

impl Cache {
    /// Returns a new cache instance.
    pub(crate) fn new<T: AsRef<Path>>(path: T) -> Result<Self, Error> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        // After 10 million bytes, sort the cache file and create new one
        opts.set_write_buffer_size(10_000_000);

        let db = DB::open(&opts, path)?;
        let write_batch = WriteBatch::default();

        Ok(Self { db, write_batch })
    }

    /// We store (key, Vec<(height, note)>).
    pub(crate) fn insert(
        &mut self,
        psk: PublicSpendKey,
        height: u64,
        note: Option<Note>,
    ) -> Result<(), Error> {
        let psk_bytes = psk.encode_to_vec();
        let mut data: KeyData;

        if let Some(data_bytes) = self.db.get(&psk_bytes)? {
            let mut source = Source::new(&data_bytes);
            // decode key data
            data = KeyData::decode(&mut source)?;

            if let Some(note) = note {
                if height > data.last_height {
                    data.last_height = height;
                }
                data.notes.insert(NoteData { height, note });
            }
        } else {
            data = KeyData {
                last_height: height,
                notes: BTreeSet::new(),
            };

            if let Some(note) = note {
                data.notes.insert(NoteData { height, note });
            }
        }

        self.write_batch.put(psk_bytes, data.encode_to_vec());

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
        let psk_bytes = psk.encode_to_vec();
        if let Some(data_bytes) = self.db.get(&psk_bytes)? {
            let mut source = Source::new(&data_bytes);
            // decode key data
            let data = KeyData::decode(&mut source)?;

            Ok(data.last_height)
        } else {
            Ok(0)
        }
    }

    /// Returns an iterator over all notes inserted for the given PSK, in order
    /// of block height.
    pub(crate) fn notes(
        &self,
        psk: PublicSpendKey,
    ) -> Result<BTreeSet<NoteData>, Error> {
        let psk_bytes = psk.encode_to_vec();

        if let Some(data_bytes) = self.db.get(&psk_bytes)? {
            let mut source = Source::new(&data_bytes);
            // decode key data
            let data = KeyData::decode(&mut source)?;

            Ok(data.notes)
        } else {
            Ok(BTreeSet::new())
        }
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
