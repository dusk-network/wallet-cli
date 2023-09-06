// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod sync;

use dusk_bls12_381_sign::PublicKey;
use dusk_bytes::{
    DeserializableSlice, Error as BytesError, Serializable, Write,
};
use dusk_pki::ViewKey;
use dusk_plonk::prelude::*;
use dusk_plonk::proof_system::Proof;
use dusk_schnorr::{Proof as SchnorrSig, Signature};
use dusk_wallet_core::{
    EnrichedNote, ProverClient, StakeInfo, StateClient, Transaction,
    UnprovenTransaction, MAX_CALL_SIZE, POSEIDON_TREE_DEPTH,
};
use dusk_wallet_core_wasm::tx::{
    CallData, Input, Output, UnprovenTransaction as UnprovenWasmTx,
};
use flume::Sender;
use phoenix_core::transaction::StakeData;
use phoenix_core::{Crossover, Fee, Note};
use poseidon_merkle::Opening as PoseidonOpening;
use rusk_abi::{ContractId, CONTRACT_ID_BYTES};
use tokio::time::{sleep, Duration};

use std::path::Path;
use std::sync::{Arc, Mutex};

use self::sync::sync_db;

use super::block::Block;
use super::cache::Cache;

use crate::rusk::{RuskHttpClient, RuskRequest};
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

const TRANSFER_CONTRACT: &str =
    "0100000000000000000000000000000000000000000000000000000000000000";

const STAKE_CONTRACT: &str =
    "0200000000000000000000000000000000000000000000000000000000000000";

// Sync every 3 seconds for now
const SYNC_INTERVAL_SECONDS: u64 = 3;

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

    pub fn compute_proof_and_propagate_wasm(
        &self,
        utx: &UnprovenWasmTx,
    ) -> anyhow::Result<Transaction> {
        self.status("Proving tx, please wait...");
        let utx_bytes = utx_to_var_bytes(utx)?;
        let prove_req = RuskRequest::new("prove_execute", utx_bytes);
        let proof_bytes =
            self.prover.call(2, "rusk", &prove_req).wait().unwrap();
        self.status("Proof success!");
        let proof = Proof::from_slice(&proof_bytes).map_err(Error::Bytes)?;
        let anchor = utx.anchor;

        let mut call = None;

        if let Some(CallData {
            contract,
            method,
            payload,
        }) = utx.clone().call
        {
            call = Some((contract.to_bytes(), method, payload));
        }

        let crossover = utx.crossover.clone().map(|e| e.crossover);
        let inputs = &utx.inputs;
        let outputs = utx.outputs.iter().map(|output| output.note).collect();
        let fee = utx.fee;
        let proof = proof.to_bytes().to_vec();
        let nullifiers = inputs.iter().map(|input| input.nullifier).collect();

        let tx = Transaction {
            nullifiers,
            outputs,
            proof,
            fee,
            anchor,
            crossover,
            call,
        };
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
    cache: Arc<Cache>,
}

impl StateStore {
    /// Creates a new state instance. Should only be called once.
    pub(crate) fn new(
        client: RuskHttpClient,
        data_dir: &Path,
        store: LocalStore,
        status: fn(&str),
    ) -> Result<Self, Error> {
        let cache = Arc::new(Cache::new(data_dir, &store, status)?);
        let inner = Mutex::new(InnerState { client, cache });

        Ok(Self {
            inner,
            status,
            store,
        })
    }

    pub async fn register_sync(
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

                if let Err(e) =
                    sync_db(&mut client, &store, cache.as_ref(), status).await
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

    #[allow(clippy::await_holding_lock)]
    pub async fn sync(&self) -> Result<(), Error> {
        let state = self.inner.lock().unwrap();
        let status = self.status;
        let store = self.store.clone();
        let mut client = state.client.clone();

        sync_db(&mut client, &store, state.cache.as_ref(), status).await
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
        self.sync().wait()?;
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

pub fn utx_to_var_bytes(tx: &UnprovenWasmTx) -> Result<Vec<u8>, Error> {
    let serialized_inputs: Vec<Vec<u8>> =
        tx.inputs.iter().map(input_to_var_bytes).collect();
    let num_inputs = tx.inputs.len();
    let total_input_len = serialized_inputs
        .iter()
        .fold(0, |len, input| len + input.len());

    let serialized_outputs: Vec<
        [u8; Note::SIZE + u64::SIZE + JubJubScalar::SIZE],
    > = tx
        .outputs
        .iter()
        .map(
            |Output {
                 note,
                 value,
                 blinder,
             }| {
                let mut buf = [0; Note::SIZE + u64::SIZE + JubJubScalar::SIZE];

                buf[..Note::SIZE].copy_from_slice(&note.to_bytes());
                buf[Note::SIZE..Note::SIZE + u64::SIZE]
                    .copy_from_slice(&value.to_bytes());
                buf[Note::SIZE + u64::SIZE
                    ..Note::SIZE + u64::SIZE + JubJubScalar::SIZE]
                    .copy_from_slice(&blinder.to_bytes());

                buf
            },
        )
        .collect();
    let num_outputs = tx.outputs.len();
    let total_output_len = serialized_outputs
        .iter()
        .fold(0, |len, output| len + output.len());

    let size = u64::SIZE
        + num_inputs * u64::SIZE
        + total_input_len
        + u64::SIZE
        + total_output_len
        + BlsScalar::SIZE
        + Fee::SIZE
        + u64::SIZE
        + tx.crossover
            .clone()
            .map_or(0, |_| Crossover::SIZE + u64::SIZE + JubJubScalar::SIZE)
        + u64::SIZE
        + tx.call
            .as_ref()
            .map(
                |CallData {
                     contract: _,
                     method,
                     payload,
                 }| {
                    CONTRACT_ID_BYTES + u64::SIZE + method.len() + payload.len()
                },
            )
            .unwrap_or(0);

    let mut buf = vec![0; size];
    let mut writer = &mut buf[..];

    writer.write(&(num_inputs as u64).to_bytes())?;
    for sinput in serialized_inputs {
        writer.write(&(sinput.len() as u64).to_bytes())?;
        writer.write(&sinput)?;
    }

    writer.write(&(num_outputs as u64).to_bytes())?;
    for soutput in serialized_outputs {
        writer.write(&soutput)?;
    }

    writer.write(&tx.anchor.to_bytes())?;
    writer.write(&tx.fee.to_bytes())?;

    let crossover = &tx.crossover;

    write_crossover_value_blinder(
        &mut writer,
        crossover.clone().map(|crossover| {
            (crossover.crossover, crossover.value, crossover.blinder)
        }),
    )?;
    write_optional_call(
        &mut writer,
        &tx.call
            .clone()
            .map(|call| (call.contract, call.method, call.payload)),
    )?;

    Ok(buf)
}

fn write_crossover_value_blinder<W: Write>(
    writer: &mut W,
    crossover: Option<(Crossover, u64, JubJubScalar)>,
) -> Result<(), BytesError> {
    match crossover {
        Some((crossover, value, blinder)) => {
            writer.write(&1_u64.to_bytes())?;
            writer.write(&crossover.to_bytes())?;
            writer.write(&value.to_bytes())?;
            writer.write(&blinder.to_bytes())?;
        }
        None => {
            writer.write(&0_u64.to_bytes())?;
        }
    }

    Ok(())
}

/// Writes an optional call into the writer, prepending it with a `u64` denoting
/// if it is present or not. This should be called at the end of writing other
/// fields since it doesn't write any information about the length of the call
/// data.
fn write_optional_call<W: Write>(
    writer: &mut W,
    call: &Option<(ContractId, String, Vec<u8>)>,
) -> Result<(), BytesError> {
    match call {
        Some((cid, cname, cdata)) => {
            writer.write(&1_u64.to_bytes())?;

            writer.write(cid.as_bytes())?;

            let cname_len = cname.len() as u64;
            writer.write(&cname_len.to_bytes())?;
            writer.write(cname.as_bytes())?;

            writer.write(cdata)?;
        }
        None => {
            writer.write(&0_u64.to_bytes())?;
        }
    };

    Ok(())
}

pub fn input_to_var_bytes(input: &Input) -> Vec<u8> {
    let affine_pkr = JubJubAffine::from(&input.pk_r_prime);

    let opening_bytes = rkyv::to_bytes::<_, 256>(&input.opening)
        .expect("Rkyv serialization should always succeed for an opening")
        .to_vec();

    let mut bytes = Vec::with_capacity(
        BlsScalar::SIZE
            + Note::SIZE
            + JubJubAffine::SIZE
            + SchnorrSig::SIZE
            + u64::SIZE
            + JubJubScalar::SIZE
            + opening_bytes.len(),
    );

    bytes.extend_from_slice(&input.nullifier.to_bytes());
    bytes.extend_from_slice(&input.note.to_bytes());
    bytes.extend_from_slice(&input.value.to_bytes());
    bytes.extend_from_slice(&input.blinder.to_bytes());
    bytes.extend_from_slice(&affine_pkr.to_bytes());
    bytes.extend_from_slice(&input.sig.to_bytes());
    bytes.extend(opening_bytes);

    bytes
}
