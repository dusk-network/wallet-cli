// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::clients::State;
use crate::Error;
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
pub struct WalletPath(pub(crate) PathBuf);

impl WalletPath {
    /// Create a new wallet path from a directory and a name
    pub fn new(dir: &Path) -> Self {
        let pb = PathBuf::from(dir);
        Self(pb)
    }

    /// Returns the filename of this path
    pub fn name(&self) -> Option<String> {
        // extract the name
        let name = self.0.file_stem()?.to_str()?;
        Some(String::from(name))
    }

    /// Returns current directory for this path
    pub fn dir(&self) -> Option<PathBuf> {
        self.0.parent().map(PathBuf::from)
    }

    /// Returns a reference to the `PathBuf` holding the path
    pub fn inner(&self) -> &PathBuf {
        &self.0
    }

    /// Sets the directory for the state cache
    pub fn set_cache_dir(path: &Path) -> Result<(), Error> {
        Ok(State::set_cache_dir(path.to_path_buf())?)
    }
}

impl FromStr for WalletPath {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let p = Path::new(s);
        Ok(Self(p.to_owned()))
    }
}

impl From<PathBuf> for WalletPath {
    fn from(p: PathBuf) -> Self {
        Self(p)
    }
}

impl From<&Path> for WalletPath {
    fn from(p: &Path) -> Self {
        Self(p.to_owned())
    }
}

impl fmt::Display for WalletPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}
