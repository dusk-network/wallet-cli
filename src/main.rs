// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod lib;
//use futures::future::ok;
pub use lib::error::{Error, ProverError, StateError, StoreError};

use clap::{AppSettings, Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use lib::clients::{Prover, State};
use lib::config::Config;
use lib::crypto::MnemSeed;
use lib::dusk::{Dusk, Lux};
use lib::gql::GraphQL;
use lib::prompt::{self, MAX_ATTEMPTS};
use lib::rusk::RuskClient;
use lib::store::LocalStore;
use lib::wallet::CliWallet;

/// The CLI Wallet
#[derive(Parser)]
#[clap(version)]
#[clap(name = "Dusk Wallet CLI")]
#[clap(author = "Dusk Network B.V.")]
#[clap(about = "A user-friendly, reliable command line interface to the Dusk wallet!", long_about = None)]
#[clap(global_setting(AppSettings::DeriveDisplayOrder))]
pub(crate) struct WalletArgs {
    /// Directory to store user data [default: `$HOME/.dusk`]
    #[clap(short, long)]
    data_dir: Option<PathBuf>,

    /// Name for your wallet [default: `$(whoami)`]
    #[clap(short = 'n', long, value_name = "NAME")]
    wallet_name: Option<String>,

    /// Path to a wallet file. Overrides `data-dir` and `wallet-name`, useful
    /// when loading a wallet that's not in the default directory.
    #[clap(short = 'f', long, parse(from_os_str), value_name = "PATH")]
    wallet_file: Option<PathBuf>,

    /// IPC method for communication with rusk [uds, tcp_ip]
    #[clap(short = 'i', long)]
    ipc_method: Option<String>,

    /// Rusk address: socket path or fully quallified URL
    #[clap(short = 'r', long)]
    rusk_addr: Option<String>,

    /// Prover service address
    #[clap(short = 'p', long)]
    prover_addr: Option<String>,

    /// Skip wallet recovery phrase (useful for headless wallet creation)
    #[clap(long)]
    skip_recovery: Option<bool>,

    /// Wait for transaction confirmation from network
    #[clap(long)]
    wait_for_tx: Option<bool>,

    /// Command
    #[clap(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Clone, Subcommand)]
enum CliCommand {
    /// Create a new wallet
    Create,

    /// Restore a lost wallet
    Restore,

    /// Check your current balance
    Balance {
        /// Key index
        #[clap(short, long, default_value_t = 0)]
        key: u64,

        /// Check maximum spendable balance
        #[clap(long)]
        spendable: bool,
    },

    /// Retrieve public spend key
    Address {
        /// Key index
        #[clap(short, long, default_value_t = 0)]
        key: u64,
    },

    /// Send DUSK through the network
    Transfer {
        /// Key index from which to send DUSK
        #[clap(short, long, default_value_t = 0)]
        key: u64,

        /// Receiver address
        #[clap(short, long)]
        rcvr: String,

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
        /// Key index from which to stake DUSK
        #[clap(short, long, default_value_t = 0)]
        key: u64,

        /// Staking key to sign this stake
        #[clap(short, long, default_value_t = 0)]
        stake_key: u64,

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
        /// Staking key used to sign the stake
        #[clap(short, long, default_value_t = 0)]
        key: u64,

        /// Check accumulated reward
        #[clap(long)]
        reward: bool,
    },

    /// Unstake a key's stake
    Unstake {
        /// Key index from which your DUSK was staked
        #[clap(short, long, default_value_t = 0)]
        key: u64,

        /// Staking key index used for this stake
        #[clap(short, long, default_value_t = 0)]
        stake_key: u64,

        /// Max amt of gas for this transaction
        #[clap(short = 'l', long)]
        gas_limit: Option<u64>,

        /// Max price you're willing to pay for gas used (in LUX)
        #[clap(short = 'p', long)]
        gas_price: Option<Lux>,
    },

    /// Withdraw accumulated reward for a stake key
    Withdraw {
        /// Key index to pay transaction costs
        #[clap(short, long, default_value_t = 0)]
        key: u64,

        /// Stake key index with the accumulated reward
        #[clap(short, long, default_value_t = 0)]
        stake_key: u64,

        /// Address to which the reward will be sent to
        #[clap(short, long)]
        refund_addr: String,

        /// Max amt of gas for this transaction
        #[clap(short = 'l', long)]
        gas_limit: Option<u64>,

        /// Max price you're willing to pay for gas used (in LUX)
        #[clap(short = 'p', long)]
        gas_price: Option<Lux>,
    },

    /// Export BLS provisioner key pair
    Export {
        /// Key index from which your DUSK was staked
        #[clap(short, long, default_value_t = 0)]
        key: u64,

        /// Don't encrypt the output file
        #[clap(long)]
        plaintext: bool,
    },

    /// Run in interactive mode (default)
    Interactive,
}

impl CliCommand {
    fn uses_wallet(&self) -> bool {
        !matches!(*self, Self::Create | Self::Restore | Self::Interactive)
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    if let Err(err) = exec().await {
        // display the error message (if any)
        println!("{}", err);
        // give cursor back to the user
        prompt::show_cursor()?;
    }
    Ok(())
}

async fn exec() -> Result<(), Error> {
    use CliCommand::*;

    // parse user args
    let args = WalletArgs::parse();
    let cmd = args.command.clone();

    // data directory needs to be clear from the start
    let data_dir = args
        .data_dir
        .as_ref()
        .cloned()
        .unwrap_or_else(LocalStore::default_data_dir);

    // create directories
    LocalStore::create_dir(&data_dir)?;

    // load configuration (or use default)
    let mut cfg = Config::load(data_dir)?;

    // merge static config with parsed args
    cfg.merge(args);

    // get command or default to interactive mode
    let cmd = cmd.unwrap_or(CliCommand::Interactive);
    let quiet = !matches!(cmd, Interactive);

    // request auth for wallet (if required)
    let pwd = if cmd.uses_wallet() || cfg.wallet.file.is_some() {
        prompt::request_auth("Please enter wallet password")
    } else {
        blake3::hash("".as_bytes())
    };

    // prepare wallet path
    let mut path_override = false;
    let wallet_path = match cfg.wallet.file {
        Some(ref p) => {
            path_override = true;
            p.with_extension("dat")
        }
        None => {
            let mut pb = PathBuf::new();
            pb.push(&cfg.wallet.data_dir);
            pb.push(&cfg.wallet.name);
            pb.set_extension("dat");
            pb
        }
    };

    // creating and restoring are on their own
    match cmd {
        Create => {
            create(&wallet_path, cfg.wallet.skip_recovery)?;
            exit();
        }
        Restore => {
            recover(&wallet_path)?;
            exit();
        }
        _ => (),
    }

    // load our store
    let store = match cmd {
        Interactive => {
            if path_override {
                LocalStore::from_file(&wallet_path, pwd)?
            } else {
                open_interactive(&cfg)?
            }
        }
        _ => LocalStore::from_file(&wallet_path, pwd)?,
    };

    // attempt to connect to rusk
    #[cfg(windows)]
    let rusk =
        RuskClient::with_tcp(&cfg.rusk.rusk_addr, &cfg.rusk.prover_addr).await;
    #[cfg(not(windows))]
    let rusk = {
        let ipc = cfg.rusk.ipc_method.as_str();
        match ipc {
            "uds" => RuskClient::with_uds(&cfg.rusk.rusk_addr).await,
            "tcp_ip" => {
                RuskClient::with_tcp(&cfg.rusk.rusk_addr, &cfg.rusk.prover_addr)
                    .await
            }
            _ => panic!("IPC method \"{}\" not supported", ipc),
        }
    };

    // graphql helper
    let gql = GraphQL::new(&cfg.chain.gql_url.clone());

    // create our wallet
    let wallet = match rusk {
        Ok(clients) => {
            // wallet-core prover client
            let prover = Prover::new(
                clients.prover,
                clients.state.clone(),
                clients.network,
                gql,
                cfg.chain.wait_for_tx,
                quiet,
            );

            // wallet-core state client
            State::set_cache_dir(cfg.wallet.data_dir.clone())?;
            let state = State::new(clients.state, quiet)?;

            // create the wallet
            CliWallet::new(cfg, store, state, prover)
        }
        Err(err) => {
            println!("\r{}", err);
            CliWallet::offline(cfg, store)
        }
    };

    // run command(s)
    match cmd {
        Interactive => wallet.interactive(),
        Balance { key, spendable } => {
            let balance = wallet.get_balance(key)?;
            if spendable {
                println!("{}", Dusk::from(balance.spendable));
            } else {
                println!("{}", Dusk::from(balance.value));
            }
            Ok(())
        }
        Address { key } => {
            let addr = wallet.get_address(key)?;
            println!("{}", addr);
            Ok(())
        }
        Transfer {
            key,
            rcvr,
            amt,
            gas_limit,
            gas_price,
        } => {
            let txh = wallet.transfer(key, &rcvr, amt, gas_limit, gas_price)?;
            println!("{}", txh);
            Ok(())
        }
        Stake {
            key,
            stake_key,
            amt,
            gas_limit,
            gas_price,
        } => {
            let txh =
                wallet.stake(key, stake_key, amt, gas_limit, gas_price)?;
            println!("{}", txh);
            Ok(())
        }
        StakeInfo { key, reward } => {
            let si = wallet.stake_info(key)?;
            let val = if reward {
                Dusk::from(si.reward)
            } else {
                match si.amount {
                    Some((value, ..)) => Dusk::from(value),
                    None => Dusk::from(0),
                }
            };
            println!("{}", val);
            Ok(())
        }
        Unstake {
            key,
            stake_key,
            gas_limit,
            gas_price,
        } => {
            let txh = wallet.unstake(key, stake_key, gas_limit, gas_price)?;
            println!("{}", txh);
            Ok(())
        }
        Withdraw {
            key,
            stake_key,
            refund_addr,
            gas_limit,
            gas_price,
        } => {
            let txh = wallet.withdraw_reward(
                key,
                stake_key,
                refund_addr,
                gas_limit,
                gas_price,
            )?;
            println!("{}", txh);
            Ok(())
        }
        Export { key, plaintext } => {
            let (pk, sk) = wallet.export_keys(key, plaintext)?;
            println!(
                "\rPub key exported to: {}\nPrv key exported to: {}",
                pk, sk
            );
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Create a new wallet
fn create(path: &Path, skip_recovery: bool) -> Result<LocalStore, Error> {
    // generate mnemonic and seed
    let ms = MnemSeed::new("");
    if !skip_recovery {
        prompt::confirm_recovery_phrase(ms.phrase);
    }

    // ask user for a password to secure the wallet
    let pwd = prompt::create_password();

    // create the store and attempt to write it to disk
    let store = LocalStore::new(path, ms.seed)?;
    store.save(pwd)?;

    // inform the user and return
    println!("> Your new wallet was created: {}", path.display());
    Ok(store)
}

/// Recover access to a lost wallet file
fn recover(path: &Path) -> Result<LocalStore, Error> {
    // ask user for 12-word recovery phrase
    let phrase = prompt::request_recovery_phrase();

    // generate wallet seed
    let ms = MnemSeed::from_phrase(&phrase, "")?;

    // ask user for a password to secure the wallet
    let pwd = prompt::create_password();

    // create the store and attempt to write it to disk
    let store = LocalStore::new(path, ms.seed)?;
    store.save(pwd)?;

    // inform the user and return
    println!("> Your wallet was restored succesfully: {}", path.display());
    Ok(store)
}

/// Loads the store interactively
fn open_interactive(cfg: &Config) -> Result<LocalStore, Error> {
    // find existing wallets
    let wallets = LocalStore::wallets_in(&cfg.wallet.data_dir)?;
    if wallets.is_empty() {
        println!("No wallet files found at {}", cfg.wallet.data_dir.display());
        return first_run(cfg, false);
    }

    // let the user choose one
    let wallet = prompt::choose_wallet(&wallets);
    let mut attempt: usize = 0;
    if let Some(p) = wallet {
        let mut store: Option<LocalStore> = None;
        while store.is_none() && attempt < MAX_ATTEMPTS {
            let pwd =
                prompt::request_auth("Please enter your wallet's password");
            let st = LocalStore::from_file(&p, pwd);
            match st {
                // match password from local store
                Ok(st) => store = Some(st),
                Err(err) => match err {
                    StoreError::InvalidPassword => {
                        println!(
                            "Wrong password, you still have {} attempt(s).",
                            MAX_ATTEMPTS - (attempt + 1)
                        );
                        thread::sleep(Duration::from_millis(1000));
                        attempt += 1;
                    }
                    _ => return Err(err.into()),
                },
            }
        }
    }

    first_run(cfg, attempt == MAX_ATTEMPTS)
}

/// Welcome the user when no wallets are found
fn first_run(cfg: &Config, should_recover: bool) -> Result<LocalStore, Error> {
    let action: usize = if should_recover {
        // user failed in filling in correct password ask to recover
        prompt::recover_wallet()
    } else {
        prompt::welcome()
    };

    if action == 0 {
        exit();
    }

    // let the user pick a name
    let name = prompt::request_wallet_name(&cfg.wallet.data_dir);
    let mut p = cfg.wallet.data_dir.clone();
    p.push(name);
    p.set_extension("dat");

    // create the store
    match action {
        1 => Ok(create(&p, false)?),
        2 => Ok(recover(&p)?),
        _ => panic!("Unrecognized option"),
    }
}

/// Terminates the program immediately with no errors
fn exit() {
    std::process::exit(0);
}
