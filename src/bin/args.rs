// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::path::PathBuf;

use super::command::Command;
use super::settings::{LogFormat, LogLevel};
use clap::Parser;

#[derive(Parser, Debug)]
#[clap(version)]
#[clap(name = "Dusk Wallet CLI")]
#[clap(author = "Dusk Network B.V.")]
#[clap(about = "A user-friendly, reliable command line interface to the Dusk wallet!", long_about = None)]
pub struct WalletArgs {
    /// Core WASM module path
    #[clap(short, long)]
    pub wallet: PathBuf,

    /// Set the password for wallet's creation
    #[clap(long, env = "RUSK_WALLET_PWD")]
    pub password: Option<String>,

    /// Output log level
    #[clap(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    /// Logging output type
    #[clap(long, value_enum, default_value_t = LogFormat::Coloured)]
    pub log_type: LogFormat,

    /// Command
    #[clap(subcommand)]
    pub command: Option<Command>,
}
