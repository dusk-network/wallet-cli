// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use clap::Subcommand;
use dusk_jubjub::BlsScalar;
use std::{fmt, path::PathBuf};

use crate::Error;
use crate::{io::prompt, WalletFile};
use dusk_wallet::{Address, Dusk, Gas, Lux, Wallet};
use dusk_wallet_core::{BalanceInfo, StakeInfo};

/// Commands that can be run against the Dusk wallet
#[derive(PartialEq, Eq, Hash, Clone, Subcommand, Debug)]
pub(crate) enum Command {
    /// Create a new wallet
    Create,

    /// Restore a lost wallet
    Restore,

    /// Check your current balance
    Balance {
        /// Address
        #[clap(short, long)]
        addr: Address,

        /// Check maximum spendable balance
        #[clap(long)]
        spendable: bool,
    },

    /// Generate new addresses or list of your existing ones
    Address {
        /// Returns list of existing addresses
        #[clap(short, long, action)]
        list: bool,
    },

    /// Send DUSK through the network
    Transfer {
        /// Address from which to send DUSK
        #[clap(short, long)]
        sndr: Option<Address>,

        /// Receiver address
        #[clap(short, long)]
        rcvr: Address,

        /// Amount of DUSK to send
        #[clap(short, long)]
        amt: Dusk,

        /// Max amt of gas for this transaction
        #[clap(short = 'l', long)]
        gas_limit: Option<u64>,

        /// Max price you're willing to pay for gas used (in LUX)
        #[clap(short = 'p', long)]
        gas_price: Option<Lux>,
    },

    /// Start staking DUSK
    Stake {
        /// Address from which to stake DUSK
        #[clap(short, long)]
        addr: Option<Address>,

        /// Amount of DUSK to stake
        #[clap(short, long)]
        amt: Dusk,

        /// Max amt of gas for this transaction
        #[clap(short = 'l', long)]
        gas_limit: Option<u64>,

        /// Max price you're willing to pay for gas used (in LUX)
        #[clap(short = 'p', long)]
        gas_price: Option<Lux>,
    },

    /// Check your stake information
    StakeInfo {
        /// Address used to stake
        #[clap(short, long)]
        addr: Option<Address>,

        /// Check accumulated reward
        #[clap(long, action)]
        reward: bool,
    },

    /// Unstake a key's stake
    Unstake {
        /// Address from which your DUSK was staked
        #[clap(short, long)]
        addr: Option<Address>,

        /// Max amt of gas for this transaction
        #[clap(short = 'l', long)]
        gas_limit: Option<u64>,

        /// Max price you're willing to pay for gas used (in LUX)
        #[clap(short = 'p', long)]
        gas_price: Option<Lux>,
    },

    /// Withdraw accumulated reward for a stake key
    Withdraw {
        /// Address to pay transaction costs
        #[clap(short, long)]
        addr: Option<Address>,

        /// Address to which the reward will be sent to
        #[clap(short, long)]
        refund_addr: Address,

        /// Max amt of gas for this transaction
        #[clap(short = 'l', long)]
        gas_limit: Option<u64>,

        /// Max price you're willing to pay for gas used (in LUX)
        #[clap(short = 'p', long)]
        gas_price: Option<Lux>,
    },

    /// Export BLS provisioner key pair
    Export {
        /// Address for which you want the exported keys
        #[clap(short, long)]
        addr: Option<Address>,

        /// Output directory for the exported keys
        #[clap(short, long)]
        dir: PathBuf,
    },

    /// Run in interactive mode (default)
    Interactive,
}

impl Command {
    /// Runs the command with the provided wallet
    pub async fn run(
        self,
        wallet: &mut Wallet<WalletFile>,
    ) -> Result<RunResult, Error> {
        match self {
            Command::Balance { addr, spendable } => {
                let balance = wallet.get_balance(&addr).await?;
                Ok(RunResult::Balance(balance, spendable))
            }
            Command::Address { list } => {
                if list {
                    Ok(RunResult::Addresses(wallet.addresses()))
                } else {
                    let addr = wallet.new_address();
                    wallet.save()?;
                    Ok(RunResult::Address(Box::new(addr)))
                }
            }
            Command::Transfer {
                sndr,
                rcvr,
                amt,
                gas_limit,
                gas_price,
            } => {
                let sender = match sndr {
                    Some(addr) => wallet.claim_as_address(addr)?,
                    None => wallet.default_address(),
                };
                let gas = gas_from_args(gas_price, gas_limit);
                let tx = wallet.transfer(&sender, &rcvr, amt, gas).await?;
                Ok(RunResult::Tx(tx.hash()))
            }
            Command::Stake {
                addr,
                amt,
                gas_limit,
                gas_price,
            } => {
                let addr = match addr {
                    Some(addr) => wallet.claim_as_address(addr)?,
                    None => wallet.default_address(),
                };
                let gas = gas_from_args(gas_price, gas_limit);
                let tx = wallet.stake(&addr, amt, gas).await?;
                Ok(RunResult::Tx(tx.hash()))
            }
            Command::StakeInfo { addr, reward } => {
                let addr = match addr {
                    Some(addr) => wallet.claim_as_address(addr)?,
                    None => wallet.default_address(),
                };
                let si = wallet.stake_info(&addr).await?;
                Ok(RunResult::StakeInfo(si, reward))
            }
            Command::Unstake {
                addr,
                gas_limit,
                gas_price,
            } => {
                let addr = match addr {
                    Some(addr) => wallet.claim_as_address(addr)?,
                    None => wallet.default_address(),
                };
                let gas = gas_from_args(gas_price, gas_limit);
                let tx = wallet.unstake(&addr, gas).await?;
                Ok(RunResult::Tx(tx.hash()))
            }
            Command::Withdraw {
                addr,
                refund_addr,
                gas_limit,
                gas_price,
            } => {
                let addr = match addr {
                    Some(addr) => wallet.claim_as_address(addr)?,
                    None => wallet.default_address(),
                };
                let gas = gas_from_args(gas_price, gas_limit);
                let tx =
                    wallet.withdraw_reward(&addr, &refund_addr, gas).await?;
                Ok(RunResult::Tx(tx.hash()))
            }
            Command::Export { addr, dir } => {
                let addr = match addr {
                    Some(addr) => wallet.claim_as_address(addr)?,
                    None => wallet.default_address(),
                };
                let pwd = prompt::request_auth("Encryption password");
                let (pub_key, key_pair) =
                    wallet.export_keys(&addr, &dir, pwd)?;
                Ok(RunResult::ExportedKeys(pub_key, key_pair))
            }
            _ => {
                // commands that don't use a wallet (like create or restore)
                // cannot be run directly
                Err(Error::NotSupported)
            }
        }
    }
}

/// Possible results of running a command in interactive mode
pub enum RunResult {
    Tx(BlsScalar),
    Balance(BalanceInfo, bool),
    StakeInfo(StakeInfo, bool),
    Address(Box<Address>),
    Addresses(Vec<Address>),
    ExportedKeys(PathBuf, PathBuf),
}

impl fmt::Display for RunResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use RunResult::*;
        match self {
            Balance(balance, _) => {
                write!(
                    f,
                    "> Total balance is: {} DUSK\n> Maximum spendable per TX is: {} DUSK",
                    Dusk::from(balance.value),
                    Dusk::from(balance.spendable)
                )
            }
            Address(addr) => {
                write!(f, "> {}", addr)
            }
            Addresses(addrs) => {
                let str_addrs = addrs
                    .iter()
                    .map(|a| format!("{}", a))
                    .collect::<Vec<String>>()
                    .join("\n>");
                write!(f, "> {}", str_addrs)
            }
            Tx(hash) => {
                write!(f, "> Transaction sent: {:x}", hash)
            }
            StakeInfo(si, _) => {
                let stake_str = match si.amount {
                    Some((value, ..)) => format!(
                        "Current stake amount is: {} DUSK",
                        Dusk::from(value)
                    ),
                    None => "No active stake found for this key".to_string(),
                };
                write!(
                    f,
                    "> {}\n> Accumulated reward is: {} DUSK",
                    stake_str,
                    Dusk::from(si.reward)
                )
            }
            ExportedKeys(pk, kp) => {
                write!(
                    f,
                    "> Public key exported to: {}\n> Key pair exported to: {}",
                    pk.display(),
                    kp.display()
                )
            }
        }
    }
}

/// Obtains a `Gas` object from runtime arguments
fn gas_from_args(price: Option<Lux>, limit: Option<u64>) -> Gas {
    let mut gas = Gas::new();
    if let Some(value) = price {
        gas.set_price(value);
    }
    if let Some(value) = limit {
        gas.set_limit(value)
    }
    gas
}
