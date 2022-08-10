// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::error::StoreError;
use crate::SEED_SIZE;
use dusk_wallet_core::Store;

/// Provides a valid wallet seed to dusk_wallet_core
#[derive(Clone)]
pub(crate) struct LocalStore {
    seed: [u8; SEED_SIZE],
}

impl Store for LocalStore {
    type Error = StoreError;

    /// Retrieves the seed used to derive keys.
    fn get_seed(&self) -> Result<[u8; SEED_SIZE], Self::Error> {
        Ok(self.seed)
    }
}

impl LocalStore {
    /// Creates a new store from a known seed
    pub(crate) fn new(seed: [u8; SEED_SIZE]) -> Self {
        LocalStore { seed }
    }
}
