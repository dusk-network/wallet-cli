// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::Command;
use clap::{AppSettings, Parser};
use std::path::PathBuf;

#[derive(Parser)]
#[clap(version)]
#[clap(name = "Dusk Wallet CLI")]
#[clap(author = "Dusk Network B.V.")]
#[clap(about = "A user-friendly, reliable command line interface to the Dusk wallet!", long_about = None)]
#[clap(global_setting(AppSettings::DeriveDisplayOrder))]
pub(crate) struct WalletArgs {
    /// Directory to store user data [default: `$HOME/.dusk`]
    #[clap(short, long)]
    pub data_dir: Option<PathBuf>,

    /// Name for your wallet [default: `$(whoami)`]
    #[clap(short = 'n', long, value_name = "NAME")]
    pub wallet_name: Option<String>,

    /// Path to a wallet file. Overrides `data-dir` and `wallet-name`, useful
    /// when loading a wallet that's not in the default directory.
    #[clap(short = 'f', long, parse(from_os_str), value_name = "PATH")]
    pub wallet_file: Option<PathBuf>,

    /// IPC method for communication with rusk [uds, tcp_ip]
    #[clap(short = 'i', long)]
    pub ipc_method: Option<String>,

    /// Rusk address: socket path or fully quallified URL
    #[clap(short = 'r', long)]
    pub rusk_addr: Option<String>,

    /// Prover service address
    #[clap(short = 'p', long)]
    pub prover_addr: Option<String>,

    /// Skip wallet recovery phrase (useful for headless wallet creation)
    #[clap(long)]
    pub skip_recovery: Option<bool>,

    /// Wait for transaction confirmation from network
    #[clap(long, action)]
    pub wait_for_tx: Option<bool>,

    /// Command
    #[clap(subcommand)]
    pub command: Option<Command>,
}
