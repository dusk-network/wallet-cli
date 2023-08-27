// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::fmt;

use clap::Subcommand;

use super::settings::Settings;
use super::Wallet;

/// Commands that can be run against the Dusk wallet
#[derive(PartialEq, Eq, Hash, Clone, Subcommand, Debug)]
pub enum Command {
    /// Check your current balance
    Balance,

    /// List your addresses
    Addresses,

    /// Send DUSK through the network
    Transfer {
        /// Address from which to send DUSK
        #[clap(short, long)]
        sndr: Option<String>,

        /// Receiver address
        #[clap(short, long)]
        rcvr: String,

        /// Amount of DUSK to send
        #[clap(short, long)]
        amt: u64,

        /// Max amt of gas for this transaction
        #[clap(short = 'l', long)]
        gas_limit: Option<u64>,

        /// Max price you're willing to pay for gas used (in LUX)
        #[clap(short = 'p', long)]
        gas_price: Option<u64>,
    },

    /// Show current settings
    Settings,
}

impl Command {
    /// Runs the command with the provided wallet
    pub async fn run(
        self,
        wallet: &mut Wallet,
        _settings: &Settings,
    ) -> anyhow::Result<RunResult> {
        match self {
            Command::Balance => {
                let state = wallet.sync().await?;
                Ok(RunResult::Balance {
                    value: state.balance,
                    maximum_transferable: state.maximum_transfer,
                })
            }
            Command::Addresses => {
                let keys = wallet.public_spend_keys().await?;
                Ok(RunResult::Addresses(keys))
            }
            Command::Transfer {
                sndr,
                rcvr,
                amt,
                gas_limit,
                gas_price,
            } => {
                let _ = sndr;
                let refund = wallet.public_spend_keys().await?[0].clone();
                wallet
                    .transfer(
                        gas_limit.unwrap_or(100),
                        gas_price.unwrap_or(1),
                        "Obfuscated",
                        rcvr,
                        0,
                        amt,
                        refund,
                    )
                    .await?;
                let state = wallet.sync().await?;
                Ok(RunResult::Balance {
                    value: state.balance,
                    maximum_transferable: state.maximum_transfer,
                })
            }
            Command::Settings => Ok(RunResult::Settings),
        }
    }
}

/// Possible results of running a command in interactive mode
pub enum RunResult {
    Balance {
        value: u64,
        maximum_transferable: u64,
    },
    Addresses(Vec<String>),
    Settings,
}

impl fmt::Display for RunResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use RunResult::*;
        match self {
            Balance {
                value,
                maximum_transferable,
            } => {
                write!(
                    f,
                    "> Total balance is: {} DUSK\n> Maximum spendable per TX is: {} DUSK",
                    value,maximum_transferable,
                )
            }
            Addresses(addrs) => {
                let str_addrs = addrs
                    .iter()
                    .map(|a| format!("{}", a))
                    .collect::<Vec<String>>()
                    .join("\n>");
                write!(f, "> {}", str_addrs)
            }
            Settings => unreachable!(),
        }
    }
}
