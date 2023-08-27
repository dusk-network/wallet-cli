// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! A wallet frontend implementation.

use std::path::Path;

use anyhow::Result;
use rand::RngCore;
use zeroize::Zeroize;

use crate::client::{Balance, Client, Execute};
use crate::{NodeClient, ProverClient, State, Storage};

/// A wallet frontend implementation
pub struct Wallet<S, N, P>
where
    S: Storage,
    N: NodeClient,
    P: ProverClient,
{
    /// Client used to interact with the wallet-core library
    pub client: Client,
    /// Storage of the wallet to persist the state
    pub storage: S,
    /// Node client to fetch network data
    pub node: N,
    /// Prover client to generate ZK proofs for transactions
    pub prover: P,
}

impl<S, N, P> Wallet<S, N, P>
where
    S: Storage,
    N: NodeClient,
    P: ProverClient,
{
    /// Creates a new wallet instance with the provided services.
    pub fn new<W>(wallet: W, storage: S, node: N, prover: P) -> Result<Self>
    where
        W: AsRef<Path>,
    {
        tracing::debug!("creating wallet instance...",);
        let client = Client::new(wallet)?;

        tracing::debug!("wallet instance created");
        Ok(Self {
            client,
            storage,
            node,
            prover,
        })
    }

    /// Returns the current state of the wallet.
    pub async fn state(&self) -> Result<State> {
        tracing::debug!("reading state from storage...");
        let state = self.storage.get_state().await;
        tracing::debug!("state read");
        state
    }

    /// Returns the public spend keys of the wallet.
    pub async fn public_spend_keys(&mut self) -> Result<Vec<String>> {
        tracing::debug!("requesting public spend keys from wallet-core...",);

        let mut secret = self.storage.get_secret().await?;
        let mut seed = self.client.seed(&secret.passphrase)?;
        secret.zeroize();

        let psk = self.client.public_spend_keys(&seed)?;
        seed.zeroize();

        tracing::debug!("public spend keys received");
        Ok(psk)
    }

    /// Performs a call to a contract method and returns the new state of the
    /// wallet.
    pub async fn call<
        Contract: AsRef<str>,
        Method: AsRef<str>,
        Payload: AsRef<[u8]>,
        Refund: AsRef<str>,
    >(
        &mut self,
        contract: Contract,
        method: Method,
        payload: Payload,
        crossover: Option<u64>,
        gas_limit: u64,
        gas_price: u64,
        refund: Refund,
    ) -> Result<State>
    where
        Contract: AsRef<str>,
        Method: AsRef<str>,
        Payload: AsRef<[u8]>,
        Refund: AsRef<str>,
    {
        Ok(self
            .execute::<_, _, _, String, String, _>(
                Some((contract, method, payload)),
                crossover,
                gas_limit,
                gas_price,
                None,
                refund,
            )
            .await?)
    }

    /// Transfer notes to a given receiver public spend key, and returns the new
    /// state of the wallet.
    pub async fn transfer<Type, Receiver, Refund>(
        &mut self,
        gas_limit: u64,
        gas_price: u64,
        r#type: Type,
        receiver: Receiver,
        ref_id: u64,
        value: u64,
        refund: Refund,
    ) -> Result<State>
    where
        Type: AsRef<str>,
        Receiver: AsRef<str>,
        Refund: AsRef<str>,
    {
        Ok(self
            .execute::<String, String, Vec<u8>, _, _, _>(
                None,
                None,
                gas_limit,
                gas_price,
                Some((r#type, receiver, ref_id, value)),
                refund,
            )
            .await?)
    }

    /// Execute a transaction, returning the new state of the wallet.
    pub async fn execute<Contract, Method, Payload, Type, Receiver, Refund>(
        &mut self,
        call: Option<(Contract, Method, Payload)>,
        crossover: Option<u64>,
        gas_limit: u64,
        gas_price: u64,
        output: Option<(Type, Receiver, u64, u64)>,
        refund: Refund,
    ) -> Result<State>
    where
        Contract: AsRef<str>,
        Method: AsRef<str>,
        Payload: AsRef<[u8]>,
        Type: AsRef<str>,
        Receiver: AsRef<str>,
        Refund: AsRef<str>,
    {
        tracing::info!("executing transaction...");

        let mut state = self.state().await?;
        let openings = self.node.get_openings(&state.notes).await?;

        let mut rng = vec![0u8; 64];
        rand::thread_rng().fill_bytes(&mut rng);

        let mut secret = self.storage.get_secret().await?;
        let mut seed = self.client.seed(&secret.passphrase)?;
        secret.zeroize();

        let Execute { tx, unspent_notes } = self.client.execute(
            &seed,
            rng,
            call,
            crossover,
            gas_limit,
            gas_price,
            &state.notes,
            openings,
            output,
            refund,
        )?;

        seed.zeroize();

        self.node.broadcast(&tx).await?;
        state.notes = unspent_notes;
        self.storage.set_state(state.clone()).await?;

        tracing::info!("transaction executed");

        Ok(state)
    }

    /// Syncrhonize the wallet to the latest state of the network.
    pub async fn sync(&mut self) -> Result<State> {
        tracing::info!("syncing wallet...");

        let state = self.state().await?;

        let mut secret = self.storage.get_secret().await?;
        let mut seed = self.client.seed(&secret.passphrase)?;
        secret.zeroize();

        let view_keys = self.client.view_keys(&seed)?;

        let (height, notes) =
            self.node.get_notes(state.last_height, &view_keys).await?;

        let notes = vec![notes, state.notes];
        let notes = self.client.merge_notes(notes)?;

        let nullifiers = self.client.nullifiers(&seed, &notes)?;
        let flags = self.node.get_nullifiers_status(&nullifiers).await?;

        let notes = self.client.filter_notes(flags, notes)?;
        let Balance {
            value,
            maximum_transfer,
        } = self.client.balance(&seed, &notes)?;
        seed.zeroize();

        let state = State {
            last_height: height,
            balance: value,
            maximum_transfer,
            notes,
        };

        self.storage.set_state(state.clone()).await?;

        tracing::info!("wallet synced");

        Ok(state)
    }
}
