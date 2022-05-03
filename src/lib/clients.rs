// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use canonical::{Canon, Source};
use dusk_bls12_381_sign::PublicKey;
use dusk_bytes::{DeserializableSlice, Serializable, Write};
use dusk_jubjub::{BlsScalar, JubJubAffine, JubJubScalar};
use dusk_pki::ViewKey;
use dusk_plonk::prelude::Proof;
use dusk_poseidon::tree::PoseidonBranch;
use dusk_schnorr::Signature;
use dusk_wallet_core::{
    ProverClient, StakeInfo, StateClient, Transaction, UnprovenTransaction,
    POSEIDON_TREE_DEPTH,
};
use phoenix_core::{Crossover, Fee, Note};
use std::path::Path;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::task::block_in_place;
use tonic::transport::Channel;

use rusk_schema::network_client::NetworkClient;
use rusk_schema::prover_client::ProverClient as GrpcProverClient;
use rusk_schema::state_client::StateClient as GrpcStateClient;
use rusk_schema::{
    ExecuteProverRequest, FindExistingNullifiersRequest, GetAnchorRequest,
    GetNotesOwnedByRequest, GetOpeningRequest, GetStakeRequest,
    PreverifyRequest, PropagateMessage, StctProverRequest,
    Transaction as TransactionProto, WfctProverRequest,
};

use super::cache::Cache;
use super::gql::{GraphQL, TxStatus};
use super::logger::status;
use crate::{ProverError, StateError};

const STCT_INPUT_SIZE: usize = Fee::SIZE
    + Crossover::SIZE
    + u64::SIZE
    + JubJubScalar::SIZE
    + BlsScalar::SIZE
    + Signature::SIZE;

const WFCT_INPUT_SIZE: usize =
    JubJubAffine::SIZE + u64::SIZE + JubJubScalar::SIZE;

/// Implementation of the ProverClient trait from wallet-core
#[derive(Debug)]
pub struct Prover {
    client: Mutex<GrpcProverClient<Channel>>,
    state: Mutex<GrpcStateClient<Channel>>,
    network: Mutex<NetworkClient<Channel>>,
    graphql: GraphQL,
    wait_for_tx: bool,
}

impl Prover {
    pub fn new(
        client: GrpcProverClient<Channel>,
        state: GrpcStateClient<Channel>,
        network: NetworkClient<Channel>,
        graphql: GraphQL,
        wait_for_tx: bool,
    ) -> Self {
        Prover {
            client: Mutex::new(client),
            state: Mutex::new(state),
            network: Mutex::new(network),
            graphql,
            wait_for_tx,
        }
    }
}

impl ProverClient for Prover {
    /// Error returned by the prover client.
    type Error = ProverError;

    /// Requests that a node prove the given transaction and later propagates it
    fn compute_proof_and_propagate(
        &self,
        utx: &UnprovenTransaction,
    ) -> Result<Transaction, Self::Error> {
        let utx_bytes = utx.to_var_bytes();
        let msg = ExecuteProverRequest { utx: utx_bytes };
        let req = tonic::Request::new(msg);

        status!("Proving tx, please wait...");
        let mut prover = self.client.lock().unwrap();
        let proof_bytes = block_in_place(move || {
            Handle::current()
                .block_on(async move { prover.prove_execute(req).await })
        })?
        .into_inner()
        .proof;
        status!("Proof success!");

        status!("Attempt to preverify tx...");
        let proof =
            Proof::from_slice(&proof_bytes).map_err(ProverError::Bytes)?;
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
        block_in_place(move || {
            Handle::current()
                .block_on(async move { state.preverify(req).await })
        })?;
        status!("Preverify success!");

        status!("Propagating tx...");
        let msg = PropagateMessage { message: tx_bytes };
        let req = tonic::Request::new(msg);

        let mut net = self.network.lock().unwrap();
        let _ = block_in_place(move || {
            Handle::current().block_on(async move { net.propagate(req).await })
        })?;
        status!("Transaction propagated!");

        if self.wait_for_tx {
            let tx_id = hex::encode(tx.hash().to_bytes());

            const TIMEOUT: i32 = 30;
            let mut i = 1;
            while i <= TIMEOUT {
                let status = self.graphql.tx_status(&tx_id)?;
                match status {
                    TxStatus::Ok => break,
                    TxStatus::Error(err) => {
                        return Err(Self::Error::Transaction(err))
                    }
                    TxStatus::NotFound => {
                        let msg = format!(
                            "Waiting for confirmation... ({}/{})",
                            i, TIMEOUT
                        );
                        status!(msg);
                        thread::sleep(Duration::from_millis(1000));
                        i += 1;
                    }
                }
            }
            status!("Transaction confirmed!");
        }

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

        status!("Requesting stct proof...");
        let mut prover = self.client.lock().unwrap();
        let res = block_in_place(move || {
            Handle::current()
                .block_on(async move { prover.prove_stct(req).await })
        })?
        .into_inner()
        .proof;
        status!("Stct proof success!");

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

        status!("Requesting wfct proof...");
        let mut prover = self.client.lock().unwrap();
        let res = block_in_place(move || {
            Handle::current()
                .block_on(async move { prover.prove_wfct(req).await })
        })?
        .into_inner()
        .proof;
        status!("Wfct proof success!");

        let mut proof_bytes = [0u8; Proof::SIZE];
        proof_bytes.copy_from_slice(&res);

        let proof = Proof::from_bytes(&proof_bytes)?;
        Ok(proof)
    }
}

/// Implementation of the StateClient trait from wallet-core
pub struct State {
    client: Mutex<GrpcStateClient<Channel>>,
    cache: Cache,
}

impl State {
    pub fn new(
        client: GrpcStateClient<Channel>,
        data_dir: &Path,
    ) -> Result<Self, StateError> {
        let cache = Cache::new(data_dir)?;
        Ok(State {
            client: Mutex::new(client),
            cache,
        })
    }
}
/// Types that are clients of the state API.
impl StateClient for State {
    /// Error returned by the node client.
    type Error = StateError;

    /// Find notes for a view key, starting from the given block height.
    fn fetch_notes(&self, vk: &ViewKey) -> Result<Vec<Note>, Self::Error> {
        status!("Fetching block height...");
        let psk = &vk.public_spend_key().to_bytes()[..];
        status!("Fetching cached notes...");
        let cached_block_height = self.cache.last_block_height(psk);
        let cached_notes = self.cache.cached_notes(psk)?;

        let msg = GetNotesOwnedByRequest {
            height: cached_block_height,
            vk: vk.to_bytes().to_vec(),
        };
        let req = tonic::Request::new(msg);

        status!("Fetching fresh notes...");
        let mut state = self.client.lock().unwrap();
        let res = block_in_place(move || {
            Handle::current()
                .block_on(async move { state.get_notes_owned_by(req).await })
        })?
        .into_inner();

        status!("Notes received!");
        status!("Handling notes...");

        // collect notes
        let mut fresh_notes: Vec<Note> = res
            .notes
            .into_iter()
            .flat_map(|n| {
                let mut bytes = [0u8; Note::SIZE];
                bytes.copy_from_slice(&n);

                let note = Note::from_bytes(&bytes).unwrap();
                let key = note.hash().to_bytes().to_vec();
                match cached_notes.contains_key(&key) {
                    true => None,
                    false => Some(note),
                }
            })
            .collect();

        if !fresh_notes.is_empty() {
            status!("Caching notes...");
            self.cache.persist_notes(psk, &fresh_notes[..])?;
            self.cache.persist_block_height(psk, res.height)?;
            status!("Cache updated!");
        }

        let mut ret: Vec<Note> = cached_notes.into_values().collect();
        ret.append(&mut fresh_notes);
        Ok(ret)
    }

    /// Fetch the current anchor of the state.
    fn fetch_anchor(&self) -> Result<BlsScalar, Self::Error> {
        let msg = GetAnchorRequest {};
        let req = tonic::Request::new(msg);

        status!("Fetching anchor...");
        let mut state = self.client.lock().unwrap();
        let res = block_in_place(move || {
            Handle::current()
                .block_on(async move { state.get_anchor(req).await })
        })?
        .into_inner()
        .anchor;
        status!("Anchor received!");

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
        let null_bytes: Vec<_> =
            nullifiers.iter().map(|s| s.to_bytes().to_vec()).collect();

        let msg = FindExistingNullifiersRequest {
            nullifiers: null_bytes,
        };
        let req = tonic::Request::new(msg);

        status!("Fetching nullifiers...");
        let mut state = self.client.lock().unwrap();
        let res = block_in_place(move || {
            Handle::current().block_on(async move {
                state.find_existing_nullifiers(req).await
            })
        })?
        .into_inner()
        .nullifiers;
        status!("Nullifiers received!");

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
    ) -> Result<PoseidonBranch<POSEIDON_TREE_DEPTH>, Self::Error> {
        let msg = GetOpeningRequest {
            note: note.to_bytes().to_vec(),
        };
        let req = tonic::Request::new(msg);

        status!("Fetching opening notes...");
        let mut state = self.client.lock().unwrap();
        let res = block_in_place(move || {
            Handle::current()
                .block_on(async move { state.get_opening(req).await })
        })?
        .into_inner()
        .branch;
        status!("Opening notes received!");

        let mut src = Source::new(&res);
        let branch = Canon::decode(&mut src)?;
        Ok(branch)
    }

    /// Queries the node for the amount staked by a key.
    fn fetch_stake(&self, pk: &PublicKey) -> Result<StakeInfo, Self::Error> {
        let msg = GetStakeRequest {
            pk: pk.to_bytes().to_vec(),
        };
        let req = tonic::Request::new(msg);

        status!("Fetching stake...");
        let mut state = self.client.lock().unwrap();
        let res = block_in_place(move || {
            Handle::current()
                .block_on(async move { state.get_stake(req).await })
        })?
        .into_inner();
        status!("Stake received!");

        let amount = res.amount.map(|a| (a.value, a.eligibility));

        Ok(StakeInfo {
            amount,
            reward: res.reward,
            counter: res.counter,
        })
    }
}
