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
use futures::StreamExt;
use phoenix_core::{Crossover, Fee, Note};
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use rusk_schema::{
    ExecuteProverRequest, FindExistingNullifiersRequest, GetAnchorRequest,
    GetNotesRequest, GetOpeningRequest, GetStakeRequest, PreverifyRequest,
    PropagateMessage, StctProverRequest, Transaction as TransactionProto,
    WfctProverRequest,
};

use super::block::Block;
use super::cache::Cache;
use super::gql::{GraphQL, TxStatus};
use super::rusk::{RuskNetworkClient, RuskProverClient, RuskStateClient};
use crate::{ProverError, StateError};
use crate::handle::status;

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
    client: Mutex<RuskProverClient>,
    state: Mutex<RuskStateClient>,
    network: Mutex<RuskNetworkClient>,
    graphql: GraphQL,
    wait_for_tx: bool,
    quiet: bool,
}

impl Prover {
    pub fn new(
        client: RuskProverClient,
        state: RuskStateClient,
        network: RuskNetworkClient,
        graphql: GraphQL,
        wait_for_tx: bool,
        quiet: bool,
    ) -> Self {
        Prover {
            client: Mutex::new(client),
            state: Mutex::new(state),
            network: Mutex::new(network),
            graphql,
            wait_for_tx,
            quiet,
        }
    }
}

impl Prover {
    /// Prints dynamic status updates to the user
    fn status(&self, status: &str) {
        if !self.quiet {
            status::status(status);
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

        self.status("Proving tx, please wait...");
        let mut prover = self.client.lock().unwrap();
        let proof_bytes = prover.prove_execute(req).wait()?.into_inner().proof;
        self.status("Proof success!");

        self.status("Attempt to preverify tx...");
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
        state.preverify(req).wait()?;
        self.status("Preverify success!");

        self.status("Propagating tx...");
        let msg = PropagateMessage { message: tx_bytes };
        let req = tonic::Request::new(msg);

        let mut net = self.network.lock().unwrap();
        net.propagate(req).wait()?;
        self.status("Transaction propagated!");

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
                        self.status(
                            format!(
                                "Waiting for confirmation... ({}/{})",
                                i, TIMEOUT
                            )
                            .as_str(),
                        );
                        thread::sleep(Duration::from_millis(1000));
                        i += 1;
                    }
                }
            }
            self.status("Transaction confirmed!");
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

/// Implementation of the StateClient trait from wallet-core
pub struct State {
    inner: Mutex<InnerState>,
    quiet: bool,
}

struct InnerState {
    client: RuskStateClient,
    cache: Cache,
}

impl State {
    /// Creates a new state instance. Should only be called once.
    ///
    /// # Panics
    /// If called before [`set_cache_dir`].
    pub fn new(
        client: RuskStateClient,
        quiet: bool,
    ) -> Result<Self, StateError> {
        let cache = Cache::new()?;
        let inner = Mutex::new(InnerState { client, cache });
        Ok(State { inner, quiet })
    }

    /// Sets the directory where the cache be stored. Should be called before
    /// [`new`].
    pub fn set_cache_dir(data_dir: PathBuf) -> Result<(), StateError> {
        Cache::set_data_path(data_dir)
    }

    /// Prints dynamic status updates to the user
    fn status(&self, status: &str) {
        if !self.quiet {
            status::status(status);
        }
    }
}

/// Types that are clients of the state API.
impl StateClient for State {
    /// Error returned by the node client.
    type Error = StateError;

    /// Find notes for a view key, starting from the given block height.
    fn fetch_notes(&self, vk: &ViewKey) -> Result<Vec<Note>, Self::Error> {
        let mut state = self.inner.lock().unwrap();

        self.status("Getting cached block height...");
        let psk = vk.public_spend_key();
        let last_height = state.cache.last_height(psk)?;

        self.status("Fetching fresh notes...");
        let msg = GetNotesRequest {
            height: last_height,
            vk: vec![], // empty vector means *all* notes will be streamed
        };
        let req = tonic::Request::new(msg);
        let mut stream = state.client.get_notes(req).wait()?.into_inner();
        self.status("Connection established...");

        self.status("Streaming notes...");

        while let Some(item) = stream.next().wait() {
            let rsp = item?;

            let note = Note::from_slice(&rsp.note)?;
            let note = match vk.owns(&note) {
                true => Some(note),
                false => None,
            };

            state.cache.insert(psk, rsp.height, note)?;
        }

        state.cache.persist()?;

        Ok(state
            .cache
            .notes(psk)?
            .into_iter()
            .map(|data| data.note)
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
    ) -> Result<PoseidonBranch<POSEIDON_TREE_DEPTH>, Self::Error> {
        let mut state = self.inner.lock().unwrap();

        let msg = GetOpeningRequest {
            note: note.to_bytes().to_vec(),
        };
        let req = tonic::Request::new(msg);

        self.status("Fetching opening notes...");
        let res = state.client.get_opening(req).wait()?.into_inner().branch;
        self.status("Opening notes received!");

        let mut src = Source::new(&res);
        let branch = Canon::decode(&mut src)?;
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

        Ok(StakeInfo {
            amount,
            reward: res.reward,
            counter: res.counter,
        })
    }
}
