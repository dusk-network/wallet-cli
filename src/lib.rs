// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk::{Dusk, Lux};

pub mod block;
pub mod cache;
pub mod clients;
pub mod crypto;
pub mod dusk;
pub mod error;
pub mod gql;

pub mod handle;
pub mod rusk;

pub mod store;

pub const SEED_SIZE: usize = 64;

pub const MAX_CONVERTIBLE: Dusk = Dusk::MAX;
pub const MIN_CONVERTIBLE: Dusk = Dusk::new(1);

pub const MIN_GAS_LIMIT: u64 = 350_000_000;
pub const DEFAULT_GAS_LIMIT: u64 = 500_000_000;

pub const DEFAULT_GAS_PRICE: Lux = 1;

pub use clients::{Prover, State};
pub use error::{Error, ProverError, StateError, StoreError};
pub use handle::arg::WalletArgs;
pub use store::LocalStore;
