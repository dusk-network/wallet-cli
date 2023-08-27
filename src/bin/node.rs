// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use dusk_bytes::Serializable;
use dusk_jubjub::{BlsScalar, JubJubScalar};
use dusk_pki::{PublicSpendKey, ViewKey};
use dusk_wallet_core::tx::UnprovenTransaction;
use dusk_wallet_core::tx::POSEIDON_TREE_ARITY;
use phoenix_core::Note;
use poseidon_merkle::{Item, Tree};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use rusk_abi::POSEIDON_TREE_DEPTH;
use tokio::sync::Mutex;

use super::settings::Settings;

pub struct Node {
    height: Arc<Mutex<u64>>,
    notes: Arc<Mutex<HashMap<u64, Note>>>,
    nullifiers: Arc<Mutex<HashSet<BlsScalar>>>,
    pos: Arc<Mutex<HashMap<BlsScalar, u64>>>,
    rng: Arc<Mutex<StdRng>>,
    tree: Arc<Mutex<Tree<(), POSEIDON_TREE_DEPTH, POSEIDON_TREE_ARITY>>>,
}

impl Node {
    pub fn new(_settings: &Settings) -> Self {
        let rng = [0xfa; 32];
        let rng = StdRng::from_seed(rng);
        Self {
            height: Arc::new(Mutex::new(0)),
            notes: Arc::new(Mutex::new(HashMap::new())),
            nullifiers: Arc::new(Mutex::new(HashSet::new())),
            pos: Arc::new(Mutex::new(HashMap::new())),
            rng: Arc::new(Mutex::new(rng)),
            tree: Arc::new(Mutex::new(Tree::new())),
        }
    }

    pub async fn increment_height(&self) {
        *self.height.lock().await += 1;
    }

    pub async fn rng(&self) -> StdRng {
        let mut rng = [0u8; 32];
        self.rng.lock().await.fill_bytes(&mut rng);
        StdRng::from_seed(rng)
    }

    pub async fn insert_note(&self, mut note: Note) {
        let mut tree = self.tree.lock().await;
        let pos = tree.len();

        note.set_pos(pos);

        self.notes.lock().await.insert(pos, note.clone());
        self.pos.lock().await.insert(note.hash(), pos);
        tree.insert(
            pos,
            Item {
                hash: note.hash(),
                data: (),
            },
        );
    }

    pub async fn mint<K>(&self, psk: K, value: u64) -> Result<()>
    where
        K: AsRef<[u8]>,
    {
        let psk = bs58::decode(psk)
            .into_vec()
            .map_err(|_| anyhow::anyhow!("invalid psk"))?;
        let mut psk_array = [0u8; PublicSpendKey::SIZE];
        psk_array.copy_from_slice(&psk);
        let psk = PublicSpendKey::from_bytes(&psk_array)
            .map_err(|_| anyhow::anyhow!("invalid psk"))?;

        let rng = &mut self.rng().await;
        let obfuscated = rng.next_u32() & 1 == 0;

        let note = if obfuscated {
            let blinder = JubJubScalar::random(rng);
            Note::obfuscated(rng, &psk, value, blinder)
        } else {
            Note::transparent(rng, &psk, value)
        };

        self.insert_note(note).await;
        self.increment_height().await;

        Ok(())
    }
}

#[async_trait]
impl dusk_wallet::NodeClient for Node {
    async fn get_notes(
        &self,
        block_height: u64,
        view_keys: &[u8],
    ) -> Result<(u64, Vec<u8>)> {
        let view_keys: Vec<ViewKey> = rkyv::from_bytes(view_keys)
            .map_err(|_| anyhow::anyhow!("failed to deserialize view keys"))?;

        let height = *self.height.lock().await;
        let notes: Vec<_> = self
            .notes
            .lock()
            .await
            .iter()
            .filter_map(|(height, note)| {
                (height >= &block_height
                    && view_keys.iter().any(|vk| vk.owns(note)))
                .then(|| note.clone())
            })
            .collect();

        let notes =
            rkyv::to_bytes::<_, { rusk_abi::ARGBUF_LEN }>(&notes)?.into_vec();

        Ok((height, notes))
    }

    async fn get_openings(&self, notes: &[u8]) -> Result<Vec<u8>> {
        let notes: Vec<Note> = rkyv::from_bytes(notes)
            .map_err(|_| anyhow::anyhow!("failed to deserialize notes"))?;

        let mut openings = Vec::with_capacity(notes.len());
        let positions = self.pos.lock().await;
        let tree = self.tree.lock().await;
        for note in notes {
            let pos = *positions
                .get(&note.hash())
                .ok_or(anyhow::anyhow!("note not found"))?;

            let opening = tree
                .opening(pos)
                .ok_or(anyhow::anyhow!("opening not found"))?;

            openings.push(opening);
        }

        let openings =
            rkyv::to_bytes::<_, { rusk_abi::ARGBUF_LEN }>(&openings)?
                .into_vec();

        Ok(openings)
    }

    async fn get_nullifiers_status(
        &self,
        nullifiers: &[u8],
    ) -> Result<Vec<bool>> {
        let nullifiers: Vec<BlsScalar> = rkyv::from_bytes(nullifiers)
            .map_err(|_| anyhow::anyhow!("failed to deserialize nullifiers"))?;

        let set = self.nullifiers.lock().await;
        let mut status = Vec::with_capacity(nullifiers.len());
        for nullifier in nullifiers {
            status.push(set.contains(&nullifier));
        }

        Ok(status)
    }

    async fn broadcast(&self, transaction: &[u8]) -> Result<()> {
        // our prover just forward the unproven transaction
        let transaction: UnprovenTransaction = rkyv::from_bytes(transaction)
            .map_err(|_| {
                anyhow::anyhow!("failed to deserialize unproven transaction")
            })?;

        let mut nullifiers = self.nullifiers.lock().await;
        for input in &transaction.inputs {
            nullifiers.insert(input.nullifier);
        }

        for output in transaction.outputs {
            self.insert_note(output.note).await;
        }

        Ok(())
    }
}
