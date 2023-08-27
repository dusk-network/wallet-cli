// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::Mutex;

use dusk_wallet::{Secret, State};

#[derive(Clone)]
pub struct Storage {
    pub secret: Secret,
    pub state: Arc<Mutex<State>>,
}

impl Storage {
    pub fn new(secret: u64) -> Self {
        let secret = Secret {
            passphrase: secret.to_le_bytes().to_vec(),
        };
        let state = State::default();
        Self {
            secret,
            state: Arc::new(Mutex::new(state)),
        }
    }
}

#[async_trait]
impl dusk_wallet::Storage for Storage {
    async fn get_secret(&self) -> Result<Secret> {
        Ok(self.secret.clone())
    }

    async fn get_state(&self) -> Result<State> {
        Ok(self.state.lock().await.clone())
    }

    async fn set_state(&self, state: State) -> Result<()> {
        *self.state.lock().await = state;
        Ok(())
    }
}
