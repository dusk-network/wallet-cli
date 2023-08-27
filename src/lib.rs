// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use anyhow::Result;
use async_trait::async_trait;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod client;
pub mod wallet;

/// A secret placeholder used to derive the wallet keys seed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret {
    /// A secret passphrase.
    pub passphrase: Vec<u8>,
}

/// The state of the wallet.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
pub struct State {
    /// The last block height that was received from the network.
    pub last_height: u64,
    /// The available balance of the wallet.
    pub balance: u64,
    /// The maximum transfer allowed in a single transaction.
    pub maximum_transfer: u64,
    /// The serialized unspent notes that belongs to this wallet.
    pub notes: Vec<u8>,
}

/// The storage definition to be consumed by the wallet.
#[async_trait]
pub trait Storage {
    /// Returns the secret to generate the keys seed.
    async fn get_secret(&self) -> Result<Secret>;

    /// Returns the last sync state.
    async fn get_state(&self) -> Result<State>;

    /// Replaces the persisted state.
    async fn set_state(&self, state: State) -> Result<()>;
}

/// The node interface required by the wallet.
#[async_trait]
pub trait NodeClient {
    /// Returns the block height and notes that are owned by the view keys,
    /// starting from the provided block height.
    async fn get_notes(
        &self,
        block_height: u64,
        view_keys: &[u8],
    ) -> Result<(u64, Vec<u8>)>;

    /// Returns the Merkle openings of the notes to a known anchor of the
    /// network.
    async fn get_openings(&self, notes: &[u8]) -> Result<Vec<u8>>;

    /// Returns the boolean status of the nullifiers, flagging as `true` if the
    /// nullifier exists on the state.
    async fn get_nullifiers_status(
        &self,
        nullifiers: &[u8],
    ) -> Result<Vec<bool>>;

    /// Broadcasts the provided transaction to the network, executing its state
    /// transition.
    async fn broadcast(&self, transaction: &[u8]) -> Result<()>;
}

/// The prover service interface required by the wallet.
#[async_trait]
pub trait ProverClient {
    /// Receives an unproven transaction and returns a proven transaction that
    /// can be sent to the network.
    async fn prove_transaction(&self, transaction: &[u8]) -> Result<Vec<u8>>;
}
