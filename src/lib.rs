// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Dusk Wallet Lib
//!
//! The `dusk_wallet` library aims to provide an easy and convenient way of
//! interfacing with the Dusk Network.
//!
//! Clients can use `Wallet` to create their Dusk wallet, send transactions
//! through the network of their choice, stake and withdraw rewards, etc.

#![deny(missing_docs)]

mod block;
mod cache;
mod clients;
mod crypto;

mod currency;
mod error;
mod rusk;
mod store;
mod wallet;

pub use currency::{Dusk, Lux};
pub use error::Error;
pub use rusk::{RuskEndpoint, TransportTCP, TransportUDS};
pub use wallet::gas;
pub use wallet::{Address, SecureWalletFile, Wallet, WalletPath};

/// The largest amount of Dusk that is possible to convert
pub const MAX_CONVERTIBLE: Dusk = Dusk::MAX;
/// The smallest amount of Dusk that is possible to convert
pub const MIN_CONVERTIBLE: Dusk = Dusk::new(1);
/// The length of an epoch in blocks
pub const EPOCH: u64 = 2160;
