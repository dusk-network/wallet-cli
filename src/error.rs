// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::clients::StateStore;
use crate::store::LocalStore;

use canonical::CanonError;
use phoenix_core::Error as PhoenixError;
use rand_core::Error as RngError;
use std::io;
use std::sync::PoisonError;
use tonic::codegen::http;

use super::clients;
/// Wallet core error
pub(crate) type CoreError =
    dusk_wallet_core::Error<LocalStore, StateStore, clients::Prover>;

/// Errors returned by this library
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Status error
    #[error(transparent)]
    Status(#[from] tonic::Status),
    /// Network error
    #[error(transparent)]
    Network(#[from] tonic::transport::Error),
    /// Rusk uri failure
    #[error("Invalid URI provided for Rusk: {0}")]
    RuskURI(#[from] http::uri::InvalidUri),
    /// Rusk connection failure
    #[error("Couldn't establish connection with Rusk: {0}")]
    RuskConn(tonic::transport::Error),
    /// Prover cluster connection failure
    #[error("Couldn't establish connection with the prover cluster: {0}")]
    ProverConn(tonic::transport::Error),
    /// Command not available in offline mode
    #[error("This command cannot be performed while offline")]
    Offline,
    /// Unauthorized access to this address
    #[error("Unauthorized access to this address")]
    Unauthorized,
    /// Filesystem errors
    #[error(transparent)]
    IO(#[from] io::Error),
    /// JSON serialization errors
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Bytes encoding errors
    #[error("A serialization error occurred: {0:?}")]
    Bytes(dusk_bytes::Error),
    /// Base58 errors
    #[error(transparent)]
    Base58(#[from] bs58::decode::Error),
    /// Canonical errors
    #[error("A serialization error occurred: {0:?}")]
    Canon(CanonError),
    /// Random number generator errors
    #[error(transparent)]
    Rng(#[from] RngError),
    /// Transaction model errors
    #[error("An error occurred in Phoenix: {0:?}")]
    Phoenix(PhoenixError),
    /// Not enough balance to perform transaction
    #[error("Insufficient balance to perform this operation")]
    NotEnoughBalance,
    /// Amount to transfer/stake cannot be zero
    #[error("Amount to transfer/stake cannot be zero")]
    AmountIsZero,
    /// Note combination for the given value is impossible given the maximum
    /// amount of inputs in a transaction
    #[error("Impossible notes' combination for the given value is")]
    NoteCombinationProblem,
    /// Not enough gas to perform this transaction
    #[error("Not enough gas to perform this transaction")]
    NotEnoughGas,
    /// Staking is only allowed when you're running your own local Rusk
    /// instance (Tip: Point `rusk_addr` to "localhost" or "127.0.0.1")
    #[error("Staking is only allowed when you're running your own local Rusk instance")]
    StakingNotAllowed,
    /// A stake already exists for this key
    #[error("A stake already exists for this key")]
    AlreadyStaked,
    /// A stake does not exist for this key
    #[error("A stake does not exist for this key")]
    NotStaked,
    /// No reward available for this key
    #[error("No reward available for this key")]
    NoReward,
    /// Invalid address
    #[error("Invalid address")]
    BadAddress,
    /// Address does not belong to this wallet
    #[error("Address does not belong to this wallet")]
    AddressNotOwned,
    /// Recovery phrase is not valid
    #[error("Invalid recovery phrase")]
    InvalidMnemonicPhrase,
    /// Path provided is not a directory
    #[error("Path provided is not a directory")]
    NotDirectory,
    /// Wallet file content is not valid
    #[error("Wallet file content is not valid")]
    WalletFileCorrupted,
    /// File version not recognized
    #[error("File version {0}.{1} not recognized")]
    UnknownFileVersion(u8, u8),
    /// Wallet file not found on disk
    #[error("Wallet file not found on disk")]
    WalletFileNotExists,
    /// A wallet file with this name already exists
    #[error("A wallet file with this name already exists")]
    WalletFileExists,
    /// Wallet file is missing
    #[error("Wallet file is missing")]
    WalletFileMissing,
    /// Wrong wallet password
    #[error("Block Mode Error")]
    BlockMode(#[from] block_modes::BlockModeError),
    /// Reached the maximum number of attempts
    #[error("Reached the maximum number of attempts")]
    AttemptsExhausted,
    /// Socket connection is not available on Windows
    #[error("Socket connection to {0} is not available on Windows")]
    SocketsNotSupported(String),
    /// Status callback needs to be set before connecting
    #[error("Status callback needs to be set before connecting")]
    StatusWalletConnected,
    /// Transaction error
    #[error("Transaction error: {0}")]
    Transaction(String),
    /// Rocksdb cache database error
    #[error("Rocks cache database error: {0}")]
    RocksDB(rocksdb::Error),
    /// Provided Network not found
    #[error(
        "Network not found, check config.toml, specify network with -n flag"
    )]
    NetworkNotFound,
    /// Trying to perform an operation on a poisioned mutex
    #[error("A Mutex was poisioned. Please wait a little to perform the next operation")]
    PoisonError,
}

impl From<dusk_bytes::Error> for Error {
    fn from(e: dusk_bytes::Error) -> Self {
        Self::Bytes(e)
    }
}

impl From<block_modes::InvalidKeyIvLength> for Error {
    fn from(_: block_modes::InvalidKeyIvLength) -> Self {
        Self::WalletFileCorrupted
    }
}

impl From<CanonError> for Error {
    fn from(e: CanonError) -> Self {
        Self::Canon(e)
    }
}

impl From<CoreError> for Error {
    fn from(e: CoreError) -> Self {
        use dusk_wallet_core::Error::*;
        match e {
            Store(err) | State(err) | Prover(err) => err,
            Canon(err) => Self::Canon(err),
            Rng(err) => Self::Rng(err),
            Bytes(err) => Self::Bytes(err),
            Phoenix(err) => Self::Phoenix(err),
            NotEnoughBalance => Self::NotEnoughBalance,
            NoteCombinationProblem => Self::NoteCombinationProblem,
            AlreadyStaked { .. } => Self::AlreadyStaked,
            NotStaked { .. } => Self::NotStaked,
            NoReward { .. } => Self::NoReward,
        }
    }
}

impl From<rocksdb::Error> for Error {
    fn from(e: rocksdb::Error) -> Self {
        Self::RocksDB(e)
    }
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_: PoisonError<T>) -> Self {
        Self::PoisonError
    }
}
