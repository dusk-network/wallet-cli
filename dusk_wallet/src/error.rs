// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::store::LocalStore;
use phoenix_core::Error as PhoenixError;
use rand_core::Error as RngError;
use std::{fmt, io};
use tonic::codegen::http;

use super::clients;
/// Wallet core error
pub(crate) type CoreError =
    dusk_wallet_core::Error<LocalStore, clients::State, clients::Prover>;

/// Errors returned by this library
pub enum Error {
    /// State Client errors
    State(StateError),
    /// Prover Client errors
    Prover(ProverError),
    /// Local Store errors
    Store(StoreError),
    /// Network error
    Network(tonic::transport::Error),
    /// Rusk uri failure
    RuskURI(http::uri::InvalidUri),
    /// Rusk connection failure
    RuskConn(tonic::transport::Error),
    /// Prover cluster connection failure
    ProverConn(tonic::transport::Error),
    /// Command not available in offline mode
    Offline,
    /// Unauthorized to access this wallet
    Unauthorized,
    /// Filesystem errors
    IO(io::Error),
    /// JSON serialization errors
    Json(serde_json::Error),
    /// Bytes encoding errors
    Bytes(dusk_bytes::Error),
    /// Base58 errors
    Base58(bs58::decode::Error),
    /// Canonical errors
    Canon(canonical::CanonError),
    /// Random number generator errors
    Rng(RngError),
    /// Transaction model errors
    Phoenix(PhoenixError),
    /// Not enough balance to perform transaction
    NotEnoughBalance,
    /// Amount to transfer/stake cannot be zero
    AmountIsZero,
    /// Note combination for the given value is impossible given the maximum
    /// amount of inputs in a transaction
    NoteCombinationProblem,
    /// Not enough gas to perform this transaction
    NotEnoughGas,
    /// Staking is only allowed when you're running your own local Rusk
    /// instance (Tip: Point `rusk_addr` to "localhost" or "127.0.0.1")
    StakingNotAllowed,
    /// A stake already exists for this key
    AlreadyStaked,
    /// A stake does not exist for this key
    NotStaked,
    /// No reward available for this key
    NoReward,
    /// Invalid address
    BadAddress,
    /// Address does not belong to this wallet
    AddressNotOwned,
    /// Recovery phrase is not valid
    InvalidMnemonicPhrase,
    /// Path provided is not a directory
    NotDirectory,
    /// Wallet file content is not valid
    WalletFileCorrupted,
    /// File version not recognized
    UnknownFileVersion(u8, u8),
    /// Wallet file not found on disk
    WalletFileNotExists,
    /// A wallet file with this name already exists
    WalletFileExists,
    /// Wallet file is missing
    WalletFileMissing,
    /// Wrong wallet password
    InvalidPassword,
    /// Socket connection is not available on Windows
    SocketsNotSupported(String),
    /// Status callback needs to be set before connecting
    StatusWalletConnected,
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::IO(e)
    }
}

impl From<dusk_bytes::Error> for Error {
    fn from(e: dusk_bytes::Error) -> Self {
        Self::Bytes(e)
    }
}

impl From<http::uri::InvalidUri> for Error {
    fn from(e: http::uri::InvalidUri) -> Self {
        Self::RuskURI(e)
    }
}

impl From<tonic::transport::Error> for Error {
    fn from(e: tonic::transport::Error) -> Self {
        Self::Network(e)
    }
}

impl From<bs58::decode::Error> for Error {
    fn from(e: bs58::decode::Error) -> Self {
        Self::Base58(e)
    }
}

impl From<block_modes::InvalidKeyIvLength> for Error {
    fn from(_: block_modes::InvalidKeyIvLength) -> Self {
        Self::WalletFileCorrupted
    }
}

impl From<block_modes::BlockModeError> for Error {
    fn from(_: block_modes::BlockModeError) -> Self {
        Self::InvalidPassword
    }
}

impl From<StateError> for Error {
    fn from(e: StateError) -> Self {
        Self::State(e)
    }
}

impl From<ProverError> for Error {
    fn from(e: ProverError) -> Self {
        Self::Prover(e)
    }
}

impl From<StoreError> for Error {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<CoreError> for Error {
    fn from(e: CoreError) -> Self {
        use dusk_wallet_core::Error as CoreErr;
        match e {
            CoreErr::Store(err) => Self::Store(err),
            CoreErr::State(err) => Self::State(err),
            CoreErr::Prover(err) => Self::Prover(err),
            CoreErr::Canon(err) => Self::Canon(err),
            CoreErr::Rng(err) => Self::Rng(err),
            CoreErr::Bytes(err) => Self::Bytes(err),
            CoreErr::Phoenix(err) => Self::Phoenix(err),
            CoreErr::NotEnoughBalance => Self::NotEnoughBalance,
            CoreErr::NoteCombinationProblem => Self::NoteCombinationProblem,
            CoreErr::AlreadyStaked { key: _, stake: _ } => Self::AlreadyStaked,
            CoreErr::NotStaked { key: _, stake: _ } => Self::NotStaked,
            CoreErr::NoReward { key: _, stake: _ } => Self::NoReward,
        }
    }
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::State(err) => write!(f, "{}", err),
            Error::Prover(err) => write!(f, "{}", err),
            Error::Store(err) => write!(f, "{}", err),
            Error::RuskURI(err) => write!(f, "Invalid URI provided for Rusk:\n{}", err),
            Error::Network(err) => write!(f, "A network error occurred while communicating with Rusk: {}", err),
            Error::RuskConn(err) => write!(f, "Couldn't establish connection with Rusk: {}\nPlease check your settings and try again.", err),
            Error::ProverConn(err) => write!(f, "Couldn't establish connection with the prover cluster: {}\nPlease check your settings and try again.", err),
            Error::Offline => write!(f, "This command cannot be performed while offline. Please configure a valid Rusk instance and try again."),
            Error::Unauthorized => write!(f, "Unauthorized to access this wallet"),
            Error::IO(err) => write!(f, "An IO error occurred:\n{}", err),
            Error::Json(err) => write!(f, "A serialization error occurred:\n{}", err),
            Error::Bytes(err) => write!(f, "A serialization error occurred:\n{:?}", err),
            Error::Base58(err) => write!(f, "A serialization error occurred:\n{}", err),
            Error::Canon(err) => write!(f, "A serialization error occurred:\n{:?}", err),
            Error::Rng(err) => write!(f, "An error occured while using the random number generator:\n{}", err),
            Error::Phoenix(err) => write!(f, "An error occured in Phoenix:\n{}", err),
            Error::NotEnoughGas => write!(f, "Not enough gas to perform this transaction"),
            Error::NotEnoughBalance => write!(f, "Insufficient balance to perform this operation"),
            Error::AmountIsZero => write!(f, "Amount to transfer/stake cannot be zero"),
            Error::NoteCombinationProblem => write!(f, "Note combination for the given value is impossible given the maximum amount of inputs in a transaction"),
            Error::StakingNotAllowed => write!(f, "Staking is only allowed when you're running your own local Rusk instance (Tip: Point `rusk_addr` to \"localhost\" or \"127.0.0.1\")"),
            Error::AlreadyStaked=> write!(f, "A stake already exists for this key"),
            Error::NotStaked => write!(f, "A stake does not exist for this key"),
            Error::NoReward => write!(f, "No reward available for this key"),
            Error::BadAddress => write!(f, "Invalid address"),
            Error::AddressNotOwned => write!(f, "Address does not belong to this wallet"),
            Error::InvalidMnemonicPhrase => write!(f, "Invalid recovery phrase"),
            Error::NotDirectory => write!(f, "Path provided is not a directory"),
            Error::WalletFileCorrupted => write!(f, "Wallet file content is not valid"),
            Error::UnknownFileVersion(major, minor) => write!(f, "File version {}.{} not recognized", major, minor),
            Error::WalletFileNotExists => write!(f, "Wallet file not found on disk"),
            Error::WalletFileExists => write!(f, "A wallet file with this name already exists"),
            Error::WalletFileMissing => write!(f, "No valid wallet path was provided"),
            Error::InvalidPassword => write!(f, "Wrong password"),
            Error::SocketsNotSupported(addr) => write!(f, "Socket connection to {} is not available on Windows", addr),
            Error::StatusWalletConnected => write!(f, "Status callback needs to be set before connecting"),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::State(err) => write!(f, "{:?}", err),
            Error::Prover(err) => write!(f, "{:?}", err),
            Error::Store(err) => write!(f, "{:?}", err),
            Error::RuskURI(err) => write!(f, "Invalid URI provided for Rusk:\n{:?}", err),
            Error::Network(err) => write!(f, "A network error occurred while communicating with Rusk:\n{:?}", err),
            Error::RuskConn(err) => write!(f, "Couldn't establish connection with Rusk:\n{:?}", err),
            Error::ProverConn(err) => write!(f, "Couldn't establish connection with the prover cluster:\n{:?}", err),
            Error::Offline => write!(f, "This command cannot be performed while offline. Please configure a valid Rusk instance and try again."),
            Error::Unauthorized => write!(f, "Unauthorized to access this wallet"),
            Error::IO(err) => write!(f, "An IO error occurred:\n{:?}", err),
            Error::Json(err) => write!(f, "A serialization error occurred:\n{:?}", err),
            Error::Bytes(err) => write!(f, "A serialization error occurred:\n{:?}", err),
            Error::Base58(err) => write!(f, "A serialization error occurred:\n{:?}", err),
            Error::Canon(err) => write!(f, "A serialization error occurred:\n{:?}", err),
            Error::Rng(err) => write!(f, "An error occured while using the random number generator:\n{:?}", err),
            Error::Phoenix(err) => write!(f, "An error occured in Phoenix:\n{:?}", err),
            Error::NotEnoughGas => write!(f, "Not enough gas to perform this transaction"),
            Error::NotEnoughBalance => write!(f, "Insufficient balance to perform this operation"),
            Error::AmountIsZero => write!(f, "Amount to transfer/stake cannot be zero"),
            Error::NoteCombinationProblem => write!(f, "Note combination for the given value is impossible given the maximum amount of inputs in a transaction"),
            Error::StakingNotAllowed => write!(f, "Staking is only allowed when you're running your own local Rusk instance (Tip: Point `rusk_addr` to \"localhost\" or \"127.0.0.1\")"),
            Error::AlreadyStaked=> write!(f, "A stake already exists for this key"),
            Error::NotStaked => write!(f, "A stake does not exist for this key"),
            Error::NoReward => write!(f, "No reward available for this key"),
            Error::BadAddress => write!(f, "Invalid address"),
            Error::AddressNotOwned => write!(f, "Address does not belong to this wallet"),
            Error::InvalidMnemonicPhrase => write!(f, "Invalid recovery phrase"),
            Error::NotDirectory => write!(f, "Path provided is not a directory"),
            Error::WalletFileCorrupted => write!(f, "Wallet file content is not valid"),
            Error::UnknownFileVersion(major, minor) => write!(f, "File version {}.{} not recognized", major, minor),
            Error::WalletFileNotExists => write!(f, "Wallet file not found on disk"),
            Error::WalletFileExists => write!(f, "A wallet file with this name already exists"),
            Error::WalletFileMissing => write!(f, "No valid wallet path was provided"),
            Error::InvalidPassword => write!(f, "Wrong password"),
            Error::SocketsNotSupported(addr) => write!(f, "Socket connection to {} is not available on Windows", addr),
            Error::StatusWalletConnected => write!(f, "Status callback needs to be set before connecting"),
        }
    }
}

/// State client errors
pub enum StateError {
    /// Status of a Rusk request
    Rusk(String),
    /// Bytes encoding errors
    Bytes(dusk_bytes::Error),
    /// Canonical errors
    Canon(canonical::CanonError),
    /// Cache persistence errors
    Cache(microkelvin::PersistError),
    /// I/O errors
    Io(io::Error),
}

impl From<microkelvin::PersistError> for StateError {
    fn from(e: microkelvin::PersistError) -> Self {
        Self::Cache(e)
    }
}

impl From<io::Error> for StateError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<dusk_bytes::Error> for StateError {
    fn from(e: dusk_bytes::Error) -> Self {
        Self::Bytes(e)
    }
}

impl From<canonical::CanonError> for StateError {
    fn from(e: canonical::CanonError) -> Self {
        Self::Canon(e)
    }
}

impl From<tonic::Status> for StateError {
    fn from(s: tonic::Status) -> Self {
        Self::Rusk(s.message().to_string())
    }
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StateError::Rusk(st) => {
                write!(f, "Rusk returned an error:\n{}", st)
            }
            StateError::Bytes(err) => {
                write!(f, "A serialization error occurred:\n{:?}", err)
            }
            StateError::Canon(err) => {
                write!(f, "A serialization error occurred:\n{:?}", err)
            }
            StateError::Cache(err) => {
                write!(f, "Failed to read/write cache:\n{:?}", err)
            }
            StateError::Io(err) => {
                write!(f, "An I/O error occurred {}", err)
            }
        }
    }
}

impl fmt::Debug for StateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StateError::Rusk(st) => {
                write!(f, "Rusk returned an error:\n{:?}", st)
            }
            StateError::Bytes(err) => {
                write!(f, "A serialization error occurred:\n{:?}", err)
            }
            StateError::Canon(err) => {
                write!(f, "A serialization error occurred:\n{:?}", err)
            }
            StateError::Cache(err) => {
                write!(f, "Failed to read/write cache:\n{:?}", err)
            }
            StateError::Io(err) => {
                write!(f, "An I/O error occurred {:?}", err)
            }
        }
    }
}

/// Prover client errors
pub enum ProverError {
    /// Status of a Rusk request
    Rusk(String),
    /// Bytes encoding errors
    Bytes(dusk_bytes::Error),
    /// Canonical errors
    Canon(canonical::CanonError),
    /// Transaction verification errors
    Transaction(String),
}

impl From<dusk_bytes::Error> for ProverError {
    fn from(e: dusk_bytes::Error) -> Self {
        Self::Bytes(e)
    }
}

impl From<canonical::CanonError> for ProverError {
    fn from(e: canonical::CanonError) -> Self {
        Self::Canon(e)
    }
}

impl From<tonic::Status> for ProverError {
    fn from(s: tonic::Status) -> Self {
        Self::Rusk(s.message().to_string())
    }
}

impl fmt::Display for ProverError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProverError::Rusk(st) => {
                write!(f, "Rusk returned an error:\n{}", st)
            }
            ProverError::Bytes(err) => {
                write!(f, "A serialization error occurred:\n{:?}", err)
            }
            ProverError::Canon(err) => {
                write!(f, "A serialization error occurred:\n{:?}", err)
            }
            ProverError::Transaction(err) => {
                write!(f, "Transaction failed: {}", err)
            }
        }
    }
}

impl fmt::Debug for ProverError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProverError::Rusk(st) => {
                write!(f, "Rusk returned an error:\n{:?}", st)
            }
            ProverError::Bytes(err) => {
                write!(f, "A serialization error occurred:\n{:?}", err)
            }
            ProverError::Canon(err) => {
                write!(f, "A serialization error occurred:\n{:?}", err)
            }
            ProverError::Transaction(err) => {
                write!(f, "Transaction failed: {:?}", err)
            }
        }
    }
}

/// Store errors
pub enum StoreError {}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "An error occurred in the store")
    }
}

impl fmt::Debug for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "An error occurred in the store")
    }
}
