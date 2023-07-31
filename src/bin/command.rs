// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod history;

use clap::Subcommand;
use dusk_bls12_381_sign::PublicKey;
use dusk_bytes::DeserializableSlice;
use dusk_plonk::prelude::BlsScalar;
use rusk_abi::hash::Hasher;
use std::{fmt, path::PathBuf};

use crate::io::prompt;
use crate::settings::Settings;
use crate::{WalletFile, WalletPath};

use dusk_wallet::gas::Gas;
use dusk_wallet::{Address, Dusk, Lux, Wallet, EPOCH, MAX_ADDRESSES};
use dusk_wallet_core::{BalanceInfo, StakeInfo};

pub use history::TransactionHistory;

/// The default stake gas limit
pub const DEFAULT_STAKE_GAS_LIMIT: u64 = 2_900_000_000;

/// Commands that can be run against the Dusk wallet
#[allow(clippy::large_enum_variant)]
#[derive(PartialEq, Eq, Hash, Clone, Subcommand, Debug)]
pub(crate) enum Command {
    /// Create a new wallet
    Create {
        /// Skip wallet recovery phrase (useful for headless wallet creation)
        #[clap(long, action)]
        skip_recovery: bool,
    },

    /// Restore a lost wallet
    Restore {
        /// Set the wallet .dat file to restore from
        #[clap(short, long)]
        file: Option<WalletPath>,
    },

    /// Check your current balance
    Balance {
        /// Address
        #[clap(short, long)]
        addr: Option<Address>,

        /// Check maximum spendable balance
        #[clap(long)]
        spendable: bool,
    },

    /// List your existing addresses and generate new ones
    Addresses {
        /// Create new address
        #[clap(short, long, action)]
        new: bool,
    },

    /// Show address transaction history
    History {
        /// Address for which you want to see the history
        #[clap(short, long)]
        addr: Option<Address>,
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

    /// Allow a provisioner key to stake
    StakeAllow {
        /// Address used to perform the operation
        #[clap(short, long)]
        addr: Option<Address>,

        /// Provisioner key to allow
        #[clap(short, long)]
        key: String,

        /// Max amt of gas for this transaction
        #[clap(short = 'l', long)]
        gas_limit: Option<u64>,

        /// Max price you're willing to pay for gas used (in LUX)
        #[clap(short = 'p', long)]
        gas_price: Option<Lux>,
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

    /// Export BLS provisioner key pair
    Export {
        /// Address for which you want the exported keys
        #[clap(short, long)]
        addr: Option<Address>,

        /// Output directory for the exported keys
        #[clap(short, long)]
        dir: PathBuf,
    },

    /// Show current settings
    Settings,
}

impl Command {
    /// Runs the command with the provided wallet
    pub async fn run(
        self,
        wallet: &mut Wallet<WalletFile>,
        settings: &Settings,
    ) -> anyhow::Result<RunResult> {
        match self {
            Command::Balance { addr, spendable } => {
                let addr = match addr {
                    Some(addr) => wallet.claim_as_address(addr)?,
                    None => wallet.default_address(),
                };

                let balance = wallet.get_balance(addr).await?;
                Ok(RunResult::Balance(balance, spendable))
            }
            Command::Addresses { new } => {
                if new {
                    if wallet.addresses().len() >= MAX_ADDRESSES {
                        println!(
                            "Cannot create more addresses, this wallet only supports upto 256 addresses. You have {} addresses already.", wallet.addresses().len()
                        );
                        std::process::exit(0);
                    }

                    let addr = wallet.new_address().clone();
                    wallet.save()?;
                    Ok(RunResult::Address(Box::new(addr)))
                } else {
                    Ok(RunResult::Addresses(wallet.addresses().clone()))
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
                let mut gas = Gas::default();
                gas.set_price(gas_price);
                gas.set_limit(gas_limit);

                let tx = wallet.transfer(sender, &rcvr, amt, gas).await?;
                Ok(RunResult::Tx(Hasher::digest(tx.to_hash_input_bytes())))
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
                let mut gas = Gas::new(DEFAULT_STAKE_GAS_LIMIT);
                gas.set_price(gas_price);
                gas.set_limit(gas_limit);

                let tx = wallet.stake(addr, amt, gas).await?;
                Ok(RunResult::Tx(Hasher::digest(tx.to_hash_input_bytes())))
            }
            Command::StakeAllow {
                addr,
                key,
                gas_limit,
                gas_price,
            } => {
                let addr = match addr {
                    Some(addr) => wallet.claim_as_address(addr)?,
                    None => wallet.default_address(),
                };

                let mut gas = Gas::new(DEFAULT_STAKE_GAS_LIMIT);
                gas.set_price(gas_price);
                gas.set_limit(gas_limit);

                let key_data = bs58::decode(key).into_vec()?;
                let key = PublicKey::from_slice(&key_data[..])
                    .map_err(dusk_wallet::Error::from)?;

                let tx = wallet.stake_allow(addr, &key, gas).await?;
                Ok(RunResult::Tx(Hasher::digest(tx.to_hash_input_bytes())))
            }
            Command::StakeInfo { addr, reward } => {
                let addr = match addr {
                    Some(addr) => wallet.claim_as_address(addr)?,
                    None => wallet.default_address(),
                };
                let si = wallet.stake_info(addr).await?;
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

                let mut gas = Gas::new(DEFAULT_STAKE_GAS_LIMIT);
                gas.set_price(gas_price);
                gas.set_limit(gas_limit);

                let tx = wallet.unstake(addr, gas).await?;
                Ok(RunResult::Tx(Hasher::digest(tx.to_hash_input_bytes())))
            }
            Command::Withdraw {
                addr,
                gas_limit,
                gas_price,
            } => {
                let addr = match addr {
                    Some(addr) => wallet.claim_as_address(addr)?,
                    None => wallet.default_address(),
                };

                let mut gas = Gas::new(DEFAULT_STAKE_GAS_LIMIT);
                gas.set_price(gas_price);
                gas.set_limit(gas_limit);

                let tx = wallet.withdraw_reward(addr, gas).await?;
                Ok(RunResult::Tx(Hasher::digest(tx.to_hash_input_bytes())))
            }
            Command::Export { addr, dir } => {
                let addr = match addr {
                    Some(addr) => wallet.claim_as_address(addr)?,
                    None => wallet.default_address(),
                };

                let pwd = prompt::request_auth(
                    "Encryption password",
                    &settings.password,
                    wallet.get_file_version()?,
                )?;

                let (pub_key, key_pair) =
                    wallet.export_keys(addr, &dir, &pwd)?;

                Ok(RunResult::ExportedKeys(pub_key, key_pair))
            }
            Command::History { addr } => {
                let addr = match addr {
                    Some(addr) => wallet.claim_as_address(addr)?,
                    None => wallet.default_address(),
                };
                let notes = wallet.get_all_notes(addr)?;

                let transactions =
                    history::transaction_from_notes(settings, notes).await?;

                Ok(RunResult::History(transactions))
            }
            Command::Create { .. } => Ok(RunResult::Create()),
            Command::Restore { .. } => Ok(RunResult::Restore()),
            Command::Settings => Ok(RunResult::Settings()),
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
    Create(),
    Restore(),
    Settings(),
    History(Vec<TransactionHistory>),
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
                    Some((value, eligibility)) => format!(
                        "Current stake amount is: {} DUSK\n> Stake eligibility from block #{} (Epoch {})",
                        Dusk::from(value),
                        eligibility,
                        eligibility / EPOCH
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
            History(transactions) => {
                writeln!(f, "{}", TransactionHistory::header())?;
                for th in transactions {
                    writeln!(f, "{th}")?;
                }
                Ok(())
            }
            Create() | Restore() | Settings() => unreachable!(),
        }
    }
}
