// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod sync;

use dusk_bls12_381_sign::PublicKey;
use dusk_bytes::{DeserializableSlice, Serializable, Write};
use dusk_pki::ViewKey;
use dusk_plonk::prelude::*;
use dusk_plonk::proof_system::Proof;
use dusk_schnorr::Signature;
use dusk_wallet_core::{
    EnrichedNote, ProverClient, StakeInfo, StateClient, Transaction,
    UnprovenTransaction, POSEIDON_TREE_DEPTH,
};
use flume::Sender;
use phoenix_core::{Crossover, Fee, Note};
use poseidon_merkle::Opening as PoseidonOpening;

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusk_schema::{
    ExecuteProverRequest, FindExistingNullifiersRequest, GetAnchorRequest,
    GetOpeningRequest, GetStakeRequest, PreverifyRequest, PropagateMessage,
    StctProverRequest, Transaction as TransactionProto, WfctProverRequest,
};

use self::sync::{sync_db, SYNC_INTERVAL_SECONDS};

use super::block::Block;
use super::cache::Cache;

use super::rusk::{RuskNetworkClient, RuskProverClient, RuskStateClient};
use crate::store::LocalStore;
use crate::Error;

const STCT_INPUT_SIZE: usize = Fee::SIZE
    + Crossover::SIZE
    + u64::SIZE
    + JubJubScalar::SIZE
    + BlsScalar::SIZE
    + Signature::SIZE;

const WFCT_INPUT_SIZE: usize =
    JubJubAffine::SIZE + u64::SIZE + JubJubScalar::SIZE;

/// Implementation of the ProverClient trait from wallet-core
pub struct Prover {
    client: Mutex<RuskProverClient>,
    state: Mutex<RuskStateClient>,
    network: Mutex<RuskNetworkClient>,
    status: fn(status: &str),
}

impl Prover {
    pub fn new(
        client: RuskProverClient,
        state: RuskStateClient,
        network: RuskNetworkClient,
    ) -> Self {
        Prover {
            client: Mutex::new(client),
            state: Mutex::new(state),
            network: Mutex::new(network),
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
        let utx_bytes = utx.to_var_bytes();
        let msg = ExecuteProverRequest { utx: utx_bytes };
        let req = tonic::Request::new(msg);

        self.status("Proving tx, please wait...");
        let mut prover = self.client.lock().unwrap();
        let proof_bytes = prover.prove_execute(req).wait()?.into_inner().proof;
        self.status("Proof success!");

        self.status("Attempt to preverify tx...");
        let proof = Proof::from_slice(&proof_bytes).map_err(Error::Bytes)?;
        let tx = utx.clone().prove(proof);
        let tx_bytes = tx.to_var_bytes();
        let tx_proto = TransactionProto {
            version: 1,
            r#type: 1,
            payload: tx_bytes.clone(),
        };
        let msg = PreverifyRequest { tx: Some(tx_proto) };
        let req = tonic::Request::new(msg);
        let mut state = self.state.lock().unwrap();
        state.preverify(req).wait()?;
        self.status("Preverify success!");

        self.status("Propagating tx...");
        let msg = PropagateMessage { message: tx_bytes };
        let req = tonic::Request::new(msg);

        let mut net = self.network.lock().unwrap();
        net.propagate(req).wait()?;
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

        let msg = StctProverRequest {
            circuit_inputs: buf.to_vec(),
        };
        let req = tonic::Request::new(msg);

        self.status("Requesting stct proof...");
        let mut prover = self.client.lock().unwrap();
        let res = prover.prove_stct(req).wait()?.into_inner().proof;
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

        let msg = WfctProverRequest {
            circuit_inputs: buf.to_vec(),
        };
        let req = tonic::Request::new(msg);

        self.status("Requesting wfct proof...");
        let mut prover = self.client.lock().unwrap();
        let res = prover.prove_wfct(req).wait()?.into_inner().proof;
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
    store: LocalStore,
    status: fn(&str),
}

struct InnerState {
    client: RuskStateClient,
    cache: Arc<Cache>,
}

use tokio::time::{sleep, Duration};

impl StateStore {
    /// Creates a new state instance. Should only be called once.
    pub(crate) fn new(
        data_dir: &Path,
        client: RuskStateClient,
        store: LocalStore,
    ) -> Result<Self, Error> {
        let cache = Arc::new(Cache::new(data_dir, &store)?);
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

    pub async fn start_sync(
        &self,
        sync_tx: Sender<String>,
    ) -> Result<(), Error> {
        let state = self.inner.lock().unwrap();
        let status = self.status;
        let store = self.store.clone();
        let mut client = state.client.clone();
        let cache = Arc::clone(&state.cache);
        let sender = Arc::new(sync_tx);

        status("Starting Sync..");

        tokio::spawn(async move {
            loop {
                let sender = Arc::clone(&sender);
                let _ = sender.send("Syncing..".to_string());

                if let Err(e) = sync_db(
                    &mut client,
                    &store,
                    cache.as_ref(),
                    status,
                    Arc::clone(&sender),
                )
                .await
                {
                    // Sender should not panic and if it does something is wrong
                    // and we should abort only when there's an error because it
                    // important to tell the user that the sync failed
                    sender
                        .send(format!("Error during sync:.. {:?}", e))
                        .unwrap();
                }

                let _ = sender.send("Syncing Complete".to_string());
                sleep(Duration::from_secs(SYNC_INTERVAL_SECONDS)).await;
            }
        });

        Ok(())
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
        let psk = vk.public_spend_key();
        let state = self.inner.lock().unwrap();

        Ok(state
            .cache
            .notes(&psk)?
            .into_iter()
            .map(|data| (data.note, data.height))
            .collect())
    }

    /// Fetch the current anchor of the state.
    fn fetch_anchor(&self) -> Result<BlsScalar, Self::Error> {
        let mut state = self.inner.lock().unwrap();

        let msg = GetAnchorRequest {};
        let req = tonic::Request::new(msg);

        self.status("Fetching anchor...");
        let res = state.client.get_anchor(req).wait()?.into_inner().anchor;
        self.status("Anchor received!");

        let mut bytes = [0u8; BlsScalar::SIZE];
        bytes.copy_from_slice(&res);
        let anchor = BlsScalar::from_bytes(&bytes)?;
        Ok(anchor)
    }

    /// Asks the node to return the nullifiers that already exist from the given
    /// nullifiers.
    fn fetch_existing_nullifiers(
        &self,
        nullifiers: &[BlsScalar],
    ) -> Result<Vec<BlsScalar>, Self::Error> {
        let mut state = self.inner.lock().unwrap();

        let null_bytes: Vec<_> =
            nullifiers.iter().map(|s| s.to_bytes().to_vec()).collect();

        let msg = FindExistingNullifiersRequest {
            nullifiers: null_bytes,
        };
        let req = tonic::Request::new(msg);

        self.status("Fetching nullifiers...");
        let res = state
            .client
            .find_existing_nullifiers(req)
            .wait()?
            .into_inner()
            .nullifiers;
        self.status("Nullifiers received!");

        let nullifiers = res
            .iter()
            .map(|n| BlsScalar::from_slice(n))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(nullifiers)
    }

    /// Queries the node to find the opening for a specific note.
    fn fetch_opening(
        &self,
        note: &Note,
    ) -> Result<PoseidonOpening<(), POSEIDON_TREE_DEPTH, 4>, Self::Error> {
        let mut state = self.inner.lock().unwrap();

        let msg = GetOpeningRequest {
            note: note.to_bytes().to_vec(),
        };
        let req = tonic::Request::new(msg);

        self.status("Fetching opening notes...");
        let res = state.client.get_opening(req).wait()?.into_inner().branch;
        self.status("Opening notes received!");

        let branch = rkyv::from_bytes(&res).map_err(|_| Error::Rkyv)?;
        Ok(branch)
    }

    /// Queries the node for the amount staked by a key.
    fn fetch_stake(&self, pk: &PublicKey) -> Result<StakeInfo, Self::Error> {
        let mut state = self.inner.lock().unwrap();

        let msg = GetStakeRequest {
            pk: pk.to_bytes().to_vec(),
        };
        let req = tonic::Request::new(msg);

        self.status("Fetching stake...");
        let res = state.client.get_stake(req).wait()?.into_inner();
        self.status("Stake received!");

        let amount = res.amount.map(|a| (a.value, a.eligibility));

        let staking_address = pk.to_bytes().to_vec();
        let staking_address = bs58::encode(staking_address).into_string();
        println!("Staking address: {}", staking_address);

        Ok(StakeInfo {
            amount,
            reward: res.reward,
            counter: res.counter,
        })
    }
}

impl StateStore {
    fn status(&self, text: &str) {
        (self.status)(text)
    }
}
