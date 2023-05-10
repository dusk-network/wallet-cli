// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use blake3::Hash;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Provides access to a secure wallet file
pub trait SecureWalletFile {
    /// Returns the path
    fn path(&self) -> &WalletPath;
    /// Returns the hashed password
    fn pwd(&self) -> Hash;
}

/// Wrapper around `PathBuf` for wallet paths
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct WalletPath {
    /// Path of the wallet file
    pub wallet: PathBuf,
    /// Directory of the cache
    pub cache: PathBuf,
    /// Name of the network
    pub network: Option<String>,
}

impl WalletPath {
    /// Create a new wallet path from a directory and a name
    pub fn new(dir: &Path) -> Self {
        let pb = PathBuf::from(dir);
        // Usually wallet path is .dusk-dir/wallet/wallet.dat, by default
        // use this dir, else specify one with set_cache_dir
        let mut cache = pb.clone();

        cache.pop();

        Self {
            wallet: pb,
            cache,
            network: None,
        }
    }

    /// Returns the filename of this path
    pub fn name(&self) -> Option<String> {
        // extract the name
        let name = self.wallet.file_stem()?.to_str()?;
        Some(String::from(name))
    }

    /// Returns current directory for this path
    pub fn dir(&self) -> Option<PathBuf> {
        self.wallet.parent().map(PathBuf::from)
    }

    /// Returns a reference to the `PathBuf` holding the path
    pub fn inner(&self) -> &PathBuf {
        &self.wallet
    }

    /// Sets the directory for the state cache
    pub fn set_cache_dir(&mut self, path: &Path) {
        self.cache = path.to_path_buf();
    }

    /// Sets the network name for different cache locations.
    /// e.g, devnet, testnet, etc.
    pub fn set_network_name(&mut self, network: Option<String>) {
        self.network = network;
    }

    /// Generates dir for cache based on network specified
    pub fn cache_dir(&self) -> PathBuf {
        let mut cache = self.cache.clone();

        if let Some(network) = &self.network {
            cache.push(network);
        } else {
            cache.push("cache");
        }

        cache
    }
}

impl FromStr for WalletPath {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let p = Path::new(s);

        Ok(Self::new(p))
    }
}

impl From<PathBuf> for WalletPath {
    fn from(p: PathBuf) -> Self {
        Self::new(&p)
    }
}

impl From<&Path> for WalletPath {
    fn from(p: &Path) -> Self {
        Self::new(p)
    }
}

impl fmt::Display for WalletPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "wallet path: {}\n\rcache path: {}\n\rnetwork: {}",
            self.wallet.display(),
            self.cache.display(),
            self.network.as_ref().unwrap_or(&"default".to_string())
        )
    }
}
