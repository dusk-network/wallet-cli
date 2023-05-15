// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::error::Error;

use std::cmp::Ordering;
use std::collections::BTreeSet;

use std::path::Path;

use canonical::{Canon, Source};
use canonical_derive::Canon;
use dusk_bytes::Serializable;
use dusk_pki::PublicSpendKey;
use phoenix_core::Note;
use rocksdb::{ColumnFamily, Options, WriteBatch, DB};
use serde::{
    ser::{SerializeSeq, SerializeStruct, Serializer},
    Deserialize, Deserializer, Serialize,
};

/// A cache of notes received from Rusk.
///
/// path is the path of the rocks db database
pub(crate) struct Cache {
    db: DB,
    write_batch: WriteBatch,
    options: Options,
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

        // Persist on function call
        let write_batch = WriteBatch::default();

        Ok(Self {
            db,
            write_batch,
            options: opts,
        })
    }

    // We store a column family named by hex representation of the psk.
    // We store key as (psk, note) and value as (KeyData)
    // The Canon of the tuple, we use it so we can have unique keys per psk and
    // note
    pub(crate) fn insert(
        &mut self,
        psk: PublicSpendKey,
        height: u64,
        note: Option<Note>,
    ) -> Result<(), Error> {
        println!("insert height: {:?}, note: {:?}", height, note);

        let cf: &ColumnFamily;
        let mut data = KeyData {
            last_height: height,
            notes: BTreeSet::new(),
        };

        let cf_name = format!("{:?}", psk);
        let key = height.to_be_bytes();

        if let Some(column_family) = self.db.cf_handle(&cf_name) {
            cf = column_family;

            if let Some(data_bytes) = self.db.get_cf(cf, &key)? {
                data = serde_json::from_slice(&data_bytes)?;
            }
        } else {
            // immediately create a cf by the hex of the psk_bytes
            self.db.create_cf(&cf_name, &Options::default())?;

            cf = self
                .db
                .cf_handle(&cf_name)
                .expect("cannot create column family for db");
        }

        if let Some(note) = note {
            data.notes.insert(NoteData { height, note });
        }

        let value = serde_json::to_string(&data)?;

        self.write_batch.put_cf(cf, key, value.as_bytes());

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
                let data: KeyData = serde_json::from_slice(&data)?;
                println!("retrive last height {:?}", data.last_height);
                return Ok(data.last_height);
            }
        };
        println!("retrive last height {:?}", 0);

        Ok(0)
    }

    /// Returns an iterator over all notes inserted for the given PSK, in order
    /// of block height.
    pub(crate) fn notes(
        &self,
        psk: PublicSpendKey,
    ) -> Result<BTreeSet<NoteData>, Error> {
        let hex = format!("{:?}", psk);

        let mut notes = BTreeSet::<NoteData>::new();

        if let Some(cf) = self.db.cf_handle(&hex) {
            let iterator =
                self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

            for i in iterator {
                let (_, data) = i?;
                let data: KeyData = serde_json::from_slice(&data)?;

                notes.extend(data.notes);
            }
        };

        println!("retrive notes {:?}", notes);

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

impl Serialize for NoteData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("NoteData", 2)?;
        state.serialize_field("height", &self.height)?;
        state.serialize_field("note", &self.note.to_bytes().to_vec())?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for NoteData {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct NoteData {
            pub height: u64,
            pub note: Vec<u8>,
        }

        let data = NoteData::deserialize(d)?;
        let height = data.height;
        let arr: [u8; Note::SIZE] = data.note.try_into().unwrap();

        let note = Note::from_bytes(&arr).unwrap();

        Ok(Self { height, note })
    }
}

#[derive(Debug, Clone, Canon, Serialize, Deserialize)]
struct KeyData {
    last_height: u64,
    notes: BTreeSet<NoteData>,
}
