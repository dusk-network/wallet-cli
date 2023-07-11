// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381_sign::PublicKey;
use dusk_bytes::{DeserializableSlice, Serializable};
use dusk_merkle::poseidon::Opening;
use dusk_pki::ViewKey;
use dusk_plonk::prelude::*;

use dusk_wallet_core::{
    EnrichedNote, StakeInfo, StateClient, Store, POSEIDON_TREE_DEPTH,
};
use futures::StreamExt;
use phoenix_core::Note;

use std::path::Path;
use std::sync::Mutex;

use rusk_schema::{
    FindExistingNullifiersRequest, GetAnchorRequest, GetNotesRequest,
    GetOpeningRequest, GetStakeRequest,
};

use super::block::Block;
use super::cache::Cache;

use super::rusk::RuskStateClient;
use crate::store::LocalStore;
use crate::{Error, MAX_ADDRESSES};

/// Implementation of the StateClient trait from wallet-core
/// inner is an option because we don't want to open the db twice and lock it
/// We construct StateStore twice
pub struct StateStore {
    inner: Mutex<InnerState>,
    status: fn(&str),
    pub(crate) store: LocalStore,
}

struct InnerState {
    client: RuskStateClient,
    cache: Cache,
}

impl StateStore {
    /// Creates a new state instance. Should only be called once.
    pub(crate) fn new(
        client: RuskStateClient,
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
        let msg = GetNotesRequest {
            height: last_height,
            vk: vec![], // empty vector means *all* notes will be streamed
        };
        let req = tonic::Request::new(msg);
        let mut stream = state.client.get_notes(req).wait()?.into_inner();
        self.status("Connection established...");

        self.status("Streaming notes...");

        self.status(format!("From block: {}", last_height).as_str());

        while let Some(item) = stream.next().wait() {
            let rsp = item?;

            last_height = std::cmp::max(last_height, rsp.height);

            let note = Note::from_slice(&rsp.note)?;

            for (ssk, vk, psk) in addresses.iter() {
                if vk.owns(&note) {
                    state.cache.insert(
                        psk,
                        rsp.height,
                        (note, note.gen_nullifier(ssk)),
                    )?;

                    break;
                }
            }
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
    ) -> Result<Opening<(), POSEIDON_TREE_DEPTH, 4>, Self::Error> {
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
