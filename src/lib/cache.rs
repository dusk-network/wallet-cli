// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::StateError;

use canonical::{Canon, Sink, Source};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use canonical_derive::Canon;
use dusk_hamt::Map;
use dusk_pki::PublicSpendKey;
use microkelvin::{BackendCtor, DiskBackend, PersistedId, Persistence};
use once_cell::sync::OnceCell;
use phoenix_core::Note;

static CACHE_DATA_PATH: OnceCell<PathBuf> = OnceCell::new();

fn backend() -> BackendCtor<DiskBackend> {
    BackendCtor::new(|| {
        DiskBackend::new(CACHE_DATA_PATH.get().unwrap().join("cache.db"))
    })
}

/// A cache of notes received from Rusk.
///
/// Before instantiating an instance with [`new`], the cache data path must be
/// set using [`set_data_path`].
#[derive(Debug, Clone)]
pub struct Cache {
    data: Map<PublicSpendKey, KeyData>,
}

impl Cache {
    /// Returns a new cache instance. Before this is called the cache data path
    /// must be set with [`set_data_path`].
    ///
    /// # Panics
    /// If called before [`set_data_path`].
    pub(crate) fn new() -> Result<Self, StateError> {
        let data_dir = CACHE_DATA_PATH.get().expect("cache path must be set");
        let id_path = data_dir.join("cache.id");

        let persisted_id = match id_path.exists() {
            true => {
                let bytes = fs::read(id_path)?;
                let mut source = Source::new(&bytes);

                Some(PersistedId::decode(&mut source)?)
            }
            false => None,
        };

        let data = persisted_id.map_or(Ok(Map::new()), |id| id.restore())?;
        Ok(Self { data })
    }

    /// Sets the cache data directory. This function can be called once and is a
    /// requirement for being able to instantiate a cache using [`new`].
    ///
    /// # Panics
    /// If data dir does not exist or is not a directory, or if called more than
    /// once.
    pub(crate) fn set_data_path(data_dir: PathBuf) -> Result<(), StateError> {
        if !(data_dir.exists() && data_dir.is_dir()) {
            panic!("cache path does not exist or is not a directory");
        }

        CACHE_DATA_PATH
            .set(data_dir)
            .expect("cache path can only be set once");

        Persistence::with_backend(&backend(), |_| Ok(()))?;

        Ok(())
    }

    /// Persist the cache to the internal backend.
    pub(crate) fn persist(&self) -> Result<(), StateError> {
        let data_dir = CACHE_DATA_PATH.get().expect("cache path must be set");
        let id_path = data_dir.join("cache.id");

        let persistence_id = Persistence::persist(&backend(), &self.data)?;

        let mut bytes = [0u8; 36];
        let mut sink = Sink::new(&mut bytes);

        persistence_id.encode(&mut sink);

        fs::write(id_path, bytes)?;

        Ok(())
    }

    /// Insert a note into the cache at the given block height. If note is
    /// `None` only the block height gets updated.
    pub(crate) fn insert(
        &mut self,
        psk: PublicSpendKey,
        height: u64,
        note: Option<Note>,
    ) -> Result<(), StateError> {
        if self.data.get(&psk)?.is_none() {
            self.data.insert(
                psk,
                KeyData {
                    last_height: 0,
                    notes: BTreeSet::new(),
                },
            )?;
        }

        let mut key_data = self.data.get_mut(&psk)?.unwrap();

        if height > key_data.last_height {
            key_data.last_height = height;
        }

        if let Some(note) = note {
            key_data.notes.insert(NoteData { height, note });
        }

        Ok(())
    }

    /// Returns the block height of the highest ever note inserted for the given
    /// PSK. If no note has ever been inserted it returns 0.
    pub(crate) fn last_height(
        &self,
        psk: PublicSpendKey,
    ) -> Result<u64, StateError> {
        Ok(self
            .data
            .get(&psk)?
            .map_or(0, |key_data| key_data.last_height))
    }

    /// Returns an iterator over all notes inserted for the given PSK, in order
    /// of block height.
    pub(crate) fn notes(
        &self,
        psk: PublicSpendKey,
    ) -> Result<BTreeSet<NoteData>, StateError> {
        Ok(self
            .data
            .get(&psk)?
            .map_or(BTreeSet::new(), |key_data| key_data.notes.clone()))
    }
}
/// Data kept about each note.
#[derive(Debug, Clone, PartialEq, Eq, Canon)]
pub struct NoteData {
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
        self.height.cmp(&other.height)
    }
}

#[derive(Debug, Clone, Canon)]
struct KeyData {
    last_height: u64,
    notes: BTreeSet<NoteData>,
}
