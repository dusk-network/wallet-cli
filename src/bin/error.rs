// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

/// Errors generated from this crate
#[derive(Debug)]
pub enum Error {
    /// TOML deserialization errors
    ConfigRead(toml::de::Error),
    /// TOML serialization errors
    ConfigWrite(toml::ser::Error),
    /// Filesystem errors
    IO(std::io::Error),
    /// GraphQL errors
    GraphQL(crate::io::GraphQLError),
    /// Dusk wallet error
    Wallet(dusk_wallet::Error),
    /// Transaction verification errors
    Transaction(String),
    /// Logging-related error
    LoggingError(String),
}

impl From<crate::io::GraphQLError> for Error {
    fn from(e: crate::io::GraphQLError) -> Self {
        Self::GraphQL(e)
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Self::ConfigRead(e)
    }
}

impl From<toml::ser::Error> for Error {
    fn from(e: toml::ser::Error) -> Self {
        Self::ConfigWrite(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl From<dusk_wallet::Error> for Error {
    fn from(e: dusk_wallet::Error) -> Self {
        Self::Wallet(e)
    }
}

impl From<tracing::dispatcher::SetGlobalDefaultError> for Error {
    fn from(err: tracing::dispatcher::SetGlobalDefaultError) -> Self {
        Self::LoggingError(err.to_string())
    }
}

impl From<tracing::metadata::ParseLevelError> for Error {
    fn from(err: tracing::metadata::ParseLevelError) -> Self {
        Self::LoggingError(err.to_string())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::IO(err) => write!(f, "An IO error occurred:\n{}", err),
            Error::GraphQL(err) => write!(f, "{}", err),
            Error::ConfigRead(err) => {
                write!(f, "Failed to read configuration file:\n{}", err)
            }
            Error::ConfigWrite(err) => {
                write!(f, "Failed to write to configuration file:\n{}", err)
            }
            Error::Wallet(err) => write!(
                f,
                "An error occured within dusk_wallet library:\n{}",
                err
            ),
            Error::Transaction(err) => write!(f, "Transaction failed: {}", err),
            Error::LoggingError(err) => write!(f, "Logging error: {}", err),
        }
    }
}
