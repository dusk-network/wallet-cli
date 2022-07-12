//! # Dusk Wallet Lib
//!
//! The `dusk_wallet` library aims to provide an easy and convenient way of
//! interfacing with the Dusk Network.
//!
//! Clients can use `Wallet` to create their Dusk wallet, send transactions
//! through the network of their choice, stake and withdraw rewards, etc.

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod block;
mod cache;
mod clients;
mod crypto;
mod status;

mod rusk;
mod dusk;
mod error;
mod store;
mod wallet;

pub use error::{Error, ProverError, StateError, StoreError};
pub use wallet::{Address, Gas, Wallet};
pub use dusk::{Dusk, Lux};
pub use rusk::{TransportTCP, TransportUDS, RuskEndpoint};

pub const SEED_SIZE: usize = 64;

pub const MAX_CONVERTIBLE: Dusk = Dusk::MAX;
pub const MIN_CONVERTIBLE: Dusk = Dusk::new(1);

pub const MIN_GAS_LIMIT: u64 = 350_000_000;
pub const DEFAULT_GAS_LIMIT: u64 = 500_000_000;

pub const DEFAULT_GAS_PRICE: Lux = 1;