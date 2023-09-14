// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod sync;

use dusk_bls12_381_sign::PublicKey;
use dusk_bytes::Serializable;
use dusk_pki::ViewKey;
use dusk_plonk::prelude::*;

use dusk_wallet_core::{EnrichedNote, StakeInfo, POSEIDON_TREE_DEPTH};

use flume::Sender;
use phoenix_core::transaction::StakeData;
use phoenix_core::Note;
use poseidon_merkle::Opening as PoseidonOpening;

use tokio::time::{sleep, Duration};

use std::path::Path;
use std::sync::{Arc, Mutex};

use self::sync::sync_db;

use super::cache::Cache;

use crate::rusk::RuskHttpClient;
use crate::store::LocalStore;
use crate::Error;

const TRANSFER_CONTRACT: &str =
    "0100000000000000000000000000000000000000000000000000000000000000";
const STAKE_CONTRACT: &str =
    "0200000000000000000000000000000000000000000000000000000000000000";

// Sync every 3 seconds for now
const SYNC_INTERVAL_SECONDS: u64 = 3;

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

    /// Fetch notes from the network
    pub async fn fetch_notes(
        &self,
        vk: &ViewKey,
    ) -> Result<Vec<EnrichedNote>, Error> {
        let psk = vk.public_spend_key();
        self.sync().await?;
        let state = self.inner.lock().unwrap();

        Ok(state
            .cache
            .notes(&psk)?
            .into_iter()
            .map(|data| (data.note, data.height))
            .collect())
    }

    /// Fetch the current anchor of the state.
    #[allow(dead_code)]
    async fn fetch_anchor(&self) -> Result<BlsScalar, Error> {
        let state = self.inner.lock().unwrap();

        self.status("Fetching anchor...");

        let anchor = state
            .client
            .contract_query::<(), 0>(TRANSFER_CONTRACT, "root", &())
            .await?;

        self.status("Anchor received!");
        let anchor = rkyv::from_bytes(&anchor).map_err(|_| Error::Rkyv)?;
        Ok(anchor)
    }

    /// Asks the node to return the nullifiers that already exist from the given
    /// nullifiers.
    pub async fn fetch_existing_nullifiers(
        &self,
        nullifiers: &[BlsScalar],
    ) -> Result<Vec<BlsScalar>, Error> {
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
            .await?;

        let nullifiers = rkyv::from_bytes(&data).map_err(|_| Error::Rkyv)?;

        Ok(nullifiers)
    }

    /// Queries the node to find the opening for a specific note.
    pub async fn fetch_opening(
        &self,
        note: &Note,
    ) -> Result<PoseidonOpening<(), POSEIDON_TREE_DEPTH, 4>, Error> {
        let state = self.inner.lock().unwrap();

        self.status("Fetching opening notes...");

        let data = state
            .client
            .contract_query::<_, 1024>(TRANSFER_CONTRACT, "opening", note.pos())
            .await?;

        self.status("Opening notes received!");

        let branch = rkyv::from_bytes(&data).map_err(|_| Error::Rkyv)?;
        Ok(branch)
    }

    /// Queries the node for the amount staked by a key.
    pub async fn fetch_stake(
        &self,
        pk: &PublicKey,
    ) -> Result<StakeInfo, Error> {
        let state = self.inner.lock().unwrap();

        self.status("Fetching stake...");

        let data = state
            .client
            .contract_query::<_, 1024>(STAKE_CONTRACT, "get_stake", pk)
            .await?;

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

    fn status(&self, text: &str) {
        (self.status)(text)
    }
}
