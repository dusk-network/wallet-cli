// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::clients::StateStore;
use crate::{Address, Error};

use dusk_bytes::{Error as BytesError, Serializable};
use dusk_wallet_core::Store;

#[derive(Clone)]
pub struct Seed([u8; 64]);

impl Default for Seed {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl Serializable<64> for Seed {
    type Error = BytesError;

    fn from_bytes(buff: &[u8; Seed::SIZE]) -> Result<Self, Self::Error> {
        Ok(Self(*buff))
    }
    fn to_bytes(&self) -> [u8; Seed::SIZE] {
        self.0
    }
}

/// Provides a valid wallet seed to dusk_wallet_core
#[derive(Clone)]
pub(crate) struct LocalStore {
    seed: Seed,
    addresses: Vec<Address>,
}

impl Store for LocalStore {
    type Error = Error;

    /// Retrieves the seed used to derive keys.
    fn get_seed(&self) -> Result<[u8; Seed::SIZE], Self::Error> {
        Ok(self.seed.to_bytes())
    }
}

impl Store for StateStore {
    type Error = Error;

    /// Retrieves the seed used to derive keys.
    fn get_seed(&self) -> Result<[u8; Seed::SIZE], Self::Error> {
        Ok(self.store.seed.to_bytes())
    }
}

impl LocalStore {
    /// Creates a new store from a known seed
    pub(crate) fn new(seed: Seed, address_count: u8) -> Self {
        let mut store = LocalStore {
            seed,
            addresses: vec![],
        };
        (0..address_count).for_each(|_| {
            store.new_address();
        });
        store
    }

    pub(crate) fn addresses(&self) -> &Vec<Address> {
        &self.addresses
    }

    /// Creates a new public address.
    /// The addresses generated are deterministic across sessions.
    pub fn new_address(&mut self) -> &Address {
        let len = self.addresses.len();
        let ssk = self
            .retrieve_ssk(len as u64)
            .expect("wallet seed should be available");
        let addr = Address::new(len as u8, ssk.public_spend_key());

        self.addresses.push(addr);
        self.addresses.last().unwrap()
    }
}
