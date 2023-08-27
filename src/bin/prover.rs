// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use anyhow::Result;
use async_trait::async_trait;
use dusk_wallet_core::tx::UnprovenTransaction;

use super::settings::Settings;

pub struct Prover(());

impl Prover {
    pub fn new(_settings: &Settings) -> Self {
        Self(())
    }
}

#[async_trait]
impl dusk_wallet::ProverClient for Prover {
    async fn prove_transaction(&self, transaction: &[u8]) -> Result<Vec<u8>> {
        let _: UnprovenTransaction =
            rkyv::from_bytes(transaction).map_err(|_| {
                anyhow::anyhow!("failed to deserialize unproven transaction")
            })?;

        Ok(transaction.to_vec())
    }
}
