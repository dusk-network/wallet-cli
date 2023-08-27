// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::path::PathBuf;

use super::node::Node;
use super::prover::Prover;
use super::storage::Storage;
use dusk_wallet::wallet::Wallet;

pub fn wallet(seed: u64) -> Wallet<Storage, Node, Prover> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let manifest = PathBuf::from(manifest).canonicalize().unwrap();
    let wasm = manifest
        .join("assets")
        .join("dusk-wallet-core-0.21.0.wasm")
        .canonicalize()
        .unwrap();

    let storage = Storage::new(seed);
    let prover = Prover::default();

    let mut rng = [0u8; 32];
    rng[..8].copy_from_slice(&seed.to_le_bytes());
    rng[8..16].copy_from_slice(&seed.to_le_bytes());
    rng[16..24].copy_from_slice(&seed.to_le_bytes());
    rng[24..].copy_from_slice(&seed.to_le_bytes());
    let node = Node::new(rng);

    Wallet::new(wasm, storage, node, prover).unwrap()
}
