// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381_sign::PublicKey;
use dusk_bytes::{DeserializableSlice, Serializable, Write};
use dusk_pki::ViewKey;
use dusk_plonk::prelude::*;
use dusk_plonk::proof_system::Proof;
use dusk_schnorr::Signature;
use dusk_wallet_core::{
    EnrichedNote, ProverClient, StakeInfo, StateClient, Store, Transaction,
    UnprovenTransaction, POSEIDON_TREE_DEPTH,
};
use futures::StreamExt;
use phoenix_core::transaction::{ArchivedTreeLeaf, StakeData, TreeLeaf};
use phoenix_core::{Crossover, Fee, Note};
use poseidon_merkle::Opening as PoseidonOpening;

use std::mem::size_of;
use std::path::Path;
use std::sync::Mutex;

use super::block::Block;
use super::cache::Cache;

use crate::rusk::{RuskHttpClient, RuskRequest};
use crate::store::LocalStore;
use crate::{Error, MAX_ADDRESSES};

const STCT_INPUT_SIZE: usize = Fee::SIZE
    + Crossover::SIZE
    + u64::SIZE
    + JubJubScalar::SIZE
    + BlsScalar::SIZE
    + Signature::SIZE;

const WFCT_INPUT_SIZE: usize =
    JubJubAffine::SIZE + u64::SIZE + JubJubScalar::SIZE;

const TRANSFER_CONTRACT: &str =
    "0100000000000000000000000000000000000000000000000000000000000000";
const STAKE_CONTRACT: &str =
    "0200000000000000000000000000000000000000000000000000000000000000";

const RKYV_TREE_LEAF_SIZE: usize = size_of::<ArchivedTreeLeaf>();

/// Implementation of the ProverClient trait from wallet-core
pub struct Prover {
    state: RuskHttpClient,
    prover: RuskHttpClient,
    status: fn(status: &str),
}

impl Prover {
    pub fn new(state: RuskHttpClient, prover: RuskHttpClient) -> Self {
        Prover {
            state,
            prover,
            status: |_| {},
        }
    }

    /// Sets the callback method to send status updates
    pub fn set_status_callback(&mut self, status: fn(&str)) {
        self.status = status;
    }
}

impl ProverClient for Prover {
    /// Error returned by the prover client.
    type Error = Error;

    /// Requests that a node prove the given transaction and later propagates it
    fn compute_proof_and_propagate(
        &self,
        utx: &UnprovenTransaction,
    ) -> Result<Transaction, Self::Error> {
        self.status("Proving tx, please wait...");
        let utx_bytes = utx.to_var_bytes();
        let prove_req = RuskRequest::new("prove_execute", utx_bytes);
        let proof_bytes = self.prover.call(2, "rusk", &prove_req).wait()?;
        self.status("Proof success!");
        let proof = Proof::from_slice(&proof_bytes).map_err(Error::Bytes)?;
        let tx = utx.clone().prove(proof);
        let tx_bytes = tx.to_var_bytes();

        self.status("Attempt to preverify tx...");
        let preverify_req = RuskRequest::new("preverify", tx_bytes.clone());
        let _ = self.state.call(2, "rusk", &preverify_req).wait()?;
        self.status("Preverify success!");

        self.status("Propagating tx...");
        let propagate_req = RuskRequest::new("propagate_tx", tx_bytes);
        let _ = self.state.call(2, "Chain", &propagate_req).wait()?;
        self.status("Transaction propagated!");

        Ok(tx)
    }

    /// Requests an STCT proof.
    fn request_stct_proof(
        &self,
        fee: &Fee,
        crossover: &Crossover,
        value: u64,
        blinder: JubJubScalar,
        address: BlsScalar,
        signature: Signature,
    ) -> Result<Proof, Self::Error> {
        let mut buf = [0; STCT_INPUT_SIZE];
        let mut writer = &mut buf[..];
        writer.write(&fee.to_bytes())?;
        writer.write(&crossover.to_bytes())?;
        writer.write(&value.to_bytes())?;
        writer.write(&blinder.to_bytes())?;
        writer.write(&address.to_bytes())?;
        writer.write(&signature.to_bytes())?;

        self.status("Requesting stct proof...");

        let prove_req = RuskRequest::new("prove_stct", buf.to_vec());
        let res = self.prover.call(2, "rusk", &prove_req).wait()?;

        self.status("Stct proof success!");

        let mut proof_bytes = [0u8; Proof::SIZE];
        proof_bytes.copy_from_slice(&res);

        let proof = Proof::from_bytes(&proof_bytes)?;
        Ok(proof)
    }

    /// Request a WFCT proof.
    fn request_wfct_proof(
        &self,
        commitment: JubJubAffine,
        value: u64,
        blinder: JubJubScalar,
    ) -> Result<Proof, Self::Error> {
        let mut buf = [0; WFCT_INPUT_SIZE];
        let mut writer = &mut buf[..];
        writer.write(&commitment.to_bytes())?;
        writer.write(&value.to_bytes())?;
        writer.write(&blinder.to_bytes())?;

        self.status("Requesting wfct proof...");
        let prove_req = RuskRequest::new("prove_wfct", buf.to_vec());
        let res = self.prover.call(2, "rusk", &prove_req).wait()?;
        self.status("Wfct proof success!");

        let mut proof_bytes = [0u8; Proof::SIZE];
        proof_bytes.copy_from_slice(&res);

        let proof = Proof::from_bytes(&proof_bytes)?;
        Ok(proof)
    }
}

impl Prover {
    fn status(&self, text: &str) {
        (self.status)(text)
    }
}

/// Implementation of the StateClient trait from wallet-core
/// inner is an option because we don't want to open the db twice and lock it
/// We construct StateStore twice
pub struct StateStore {
    inner: Mutex<InnerState>,
    status: fn(&str),
    pub(crate) store: LocalStore,
}

struct InnerState {
    client: RuskHttpClient,
    cache: Cache,
}

impl StateStore {
    /// Creates a new state instance. Should only be called once.
    pub(crate) fn new(
        client: RuskHttpClient,
        data_dir: &Path,
        store: LocalStore,
    ) -> Result<Self, Error> {
        let cache = Cache::new(data_dir, &store)?;
        let inner = Mutex::new(InnerState { client, cache });

        Ok(Self {
            inner,
            status: |_| {},
            store,
        })
    }

    /// Sets the callback method to send status updates
    pub fn set_status_callback(&mut self, status: fn(&str)) {
        self.status = status;
    }
}

/// Types that are clients of the state API.
impl StateClient for StateStore {
    /// Error returned by the node client.
    type Error = Error;

    /// Find notes for a view key, starting from the given block height.
    fn fetch_notes(
        &self,
        vk: &ViewKey,
    ) -> Result<Vec<EnrichedNote>, Self::Error> {
        let mut state = self.inner.lock().unwrap();

        let addresses: Vec<_> = (0..MAX_ADDRESSES)
            .flat_map(|i| self.store.retrieve_ssk(i as u64))
            .map(|ssk| {
                let vk = ssk.view_key();
                let psk = vk.public_spend_key();
                (ssk, vk, psk)
            })
            .collect();

        self.status("Getting cached block height...");
        let psk = vk.public_spend_key();
        let mut last_height = state.cache.last_height()?;

        self.status("Fetching fresh notes...");
        // let mut stream = state.client.get_notes(req).wait()?.into_inner();
        let req = rkyv::to_bytes::<_, 8>(&last_height)
            .map_err(|_| Error::Rkyv)?
            .to_vec();
        let mut stream = state
            .client
            .call_raw(
                1,
                TRANSFER_CONTRACT,
                &RuskRequest::new("leaves_from_height", req),
                true,
            )
            .wait()?
            .bytes_stream();
        self.status("Connection established...");

        self.status("Streaming notes...");

        self.status(format!("From block: {}", last_height).as_str());

        // This buffer is needed because `.bytes_stream();` introduce additional
        // spliting of chunks according to it's own buffer
        let mut buffer = vec![];

        while let Some(http_chunk) = stream.next().wait() {
            buffer.extend_from_slice(&http_chunk?);

            let mut leaf_chunk = buffer.chunks_exact(RKYV_TREE_LEAF_SIZE);

            for leaf_bytes in leaf_chunk.by_ref() {
                let TreeLeaf { block_height, note } =
                    rkyv::from_bytes(leaf_bytes).map_err(|_| Error::Rkyv)?;

                last_height = std::cmp::max(last_height, block_height);

                for (ssk, vk, psk) in addresses.iter() {
                    if vk.owns(&note) {
                        let note_data = (note, note.gen_nullifier(ssk));
                        state.cache.insert(psk, block_height, note_data)?;

                        break;
                    }
                }
            }
            buffer = leaf_chunk.remainder().to_vec();
        }

        println!("Last block: {}", last_height);

        state.cache.persist(last_height)?;

        Ok(state
            .cache
            .notes(&psk)?
            .into_iter()
            .map(|data| (data.note, data.height))
            .collect())
    }

    /// Fetch the current anchor of the state.
    fn fetch_anchor(&self) -> Result<BlsScalar, Self::Error> {
        let state = self.inner.lock().unwrap();

        self.status("Fetching anchor...");

        let anchor = state
            .client
            .contract_query::<(), 0>(TRANSFER_CONTRACT, "root", &())
            .wait()?;
        self.status("Anchor received!");
        let anchor = rkyv::from_bytes(&anchor).map_err(|_| Error::Rkyv)?;
        Ok(anchor)
    }

    /// Asks the node to return the nullifiers that already exist from the given
    /// nullifiers.
    fn fetch_existing_nullifiers(
        &self,
        nullifiers: &[BlsScalar],
    ) -> Result<Vec<BlsScalar>, Self::Error> {
        let state = self.inner.lock().unwrap();

        self.status("Fetching nullifiers...");
        let nullifiers = nullifiers.to_vec();
        let data = state
            .client
            .contract_query::<_, 1024>(
                TRANSFER_CONTRACT,
                "existing_nullifiers",
                &nullifiers,
            )
            .wait()?;

        let nullifiers = rkyv::from_bytes(&data).map_err(|_| Error::Rkyv)?;

        Ok(nullifiers)
    }

    /// Queries the node to find the opening for a specific note.
    fn fetch_opening(
        &self,
        note: &Note,
    ) -> Result<PoseidonOpening<(), POSEIDON_TREE_DEPTH, 4>, Self::Error> {
        let state = self.inner.lock().unwrap();

        self.status("Fetching opening notes...");

        let data = state
            .client
            .contract_query::<_, 1024>(TRANSFER_CONTRACT, "opening", note.pos())
            .wait()?;

        self.status("Opening notes received!");

        let branch = rkyv::from_bytes(&data).map_err(|_| Error::Rkyv)?;
        Ok(branch)
    }

    /// Queries the node for the amount staked by a key.
    fn fetch_stake(&self, pk: &PublicKey) -> Result<StakeInfo, Self::Error> {
        let state = self.inner.lock().unwrap();

        self.status("Fetching stake...");

        let data = state
            .client
            .contract_query::<_, 1024>(STAKE_CONTRACT, "get_stake", pk)
            .wait()?;

        let res: Option<StakeData> =
            rkyv::from_bytes(&data).map_err(|_| Error::Rkyv)?;
        self.status("Stake received!");

        let stake = res.ok_or(Error::NotStaked).map(
            |StakeData {
                 amount,
                 reward,
                 counter,
             }| StakeInfo {
                amount,
                reward,
                counter,
            },
        )?;
        let staking_address = pk.to_bytes().to_vec();
        let staking_address = bs58::encode(staking_address).into_string();
        println!("Staking address: {}", staking_address);

        Ok(stake)
    }
}

impl StateStore {
    fn status(&self, text: &str) {
        (self.status)(text)
    }
}
