// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::{DeserializableSlice, Serializable, Write};
use dusk_plonk::prelude::*;
use dusk_schnorr::Signature;
use dusk_wallet_core::{ProverClient, Transaction, UnprovenTransaction};
use phoenix_core::{Crossover, Fee};

use std::sync::Mutex;

use rusk_schema::{
    ExecuteProverRequest, PreverifyRequest, PropagateMessage,
    StctProverRequest, Transaction as TransactionProto, WfctProverRequest,
};

use super::block::Block;
use super::rusk::{RuskNetworkClient, RuskProverClient, RuskStateClient};

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
