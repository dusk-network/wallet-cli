// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod command;
mod error;
mod interactive;
mod io;
mod menu;

pub(crate) use command::{Command, RunResult};
pub(crate) use error::Error;
pub(crate) use menu::Menu;

use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use tracing::{error, warn, Level};

use bip39::{Language, Mnemonic, MnemonicType};
use blake3::Hash;

#[cfg(not(windows))]
use dusk_wallet::TransportUDS;

use dusk_wallet::{Dusk, SecureWalletFile, TransportTCP, Wallet, WalletPath};

use io::{prompt, status};
use io::{Config, GraphQL, WalletArgs};

#[derive(Clone)]
pub(crate) struct WalletFile {
    path: WalletPath,
    pwd: Hash,
}

impl SecureWalletFile for WalletFile {
    fn path(&self) -> &WalletPath {
        &self.path
    }

    fn pwd(&self) -> Hash {
        self.pwd
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    if let Err(err) = exec().await {
        // display the error message (if any)
        error!("{}", err);
        // give cursor back to the user
        io::prompt::show_cursor()?;
    }
    Ok(())
}

async fn exec() -> Result<(), Error> {
    // parse user args
    let args = WalletArgs::parse();
    let cmd = args.command.clone();

    // set symbols to ASCII for Windows terminal compatibility
    #[cfg(windows)]
    requestty::symbols::set(requestty::symbols::ASCII);

    // data directory needs to be clear from the start
    let data_dir = args
        .data_dir
        .as_ref()
        .cloned()
        .unwrap_or_else(WalletPath::default_dir);

    // create directories
    fs::create_dir_all(&data_dir)?;

    // set cache directory straight away
    WalletPath::set_cache_dir(&data_dir)?;

    // load configuration (or use default)
    let mut cfg = Config::load(data_dir)?;

    // merge static config with parsed args
    cfg.merge(args);

    // generate a subscriber with the desired log level
    let level = Level::from_str(cfg.logging.level.as_str())?;
    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_max_level(level)
        .with_writer(std::io::stderr);

    // set the subscriber as global
    match cfg.logging.r#type.as_str() {
        "json" => {
            let subscriber = subscriber.json().flatten_event(true).finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
        "plain" => {
            let subscriber = subscriber.with_ansi(false).finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
        "coloured" => {
            let subscriber = subscriber.finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
        _ => unreachable!(),
    };

    // get command or default to interactive mode
    let cmd = cmd.unwrap_or(Command::Interactive);

    // prepare wallet path
    let wallet_path = match cfg.wallet.file {
        Some(ref p) => WalletPath::from(p.with_extension("dat")),
        None => {
            let mut pb = PathBuf::new();
            pb.push(&cfg.wallet.data_dir);
            pb.push(&cfg.wallet.name);
            pb.set_extension("dat");
            WalletPath::from(pb)
        }
    };

    // get our wallet ready
    let mut wallet: Wallet<WalletFile> = match cmd {
        Command::Create => {
            // create a new randomly generated mnemonic phrase
            let mnemonic =
                Mnemonic::new(MnemonicType::Words12, Language::English);
            // ask user for a password to secure the wallet
            let pwd = prompt::create_password();
            // skip phrase confirmation if explicitly
            if !cfg.wallet.skip_recovery {
                prompt::confirm_recovery_phrase(&mnemonic);
            }
            // create wallet
            let mut w = Wallet::new(mnemonic)?;
            w.save_to(WalletFile {
                path: wallet_path,
                pwd,
            })?;
            w
        }
        Command::Restore => {
            // ask user for 12-word recovery phrase
            let phrase = prompt::request_recovery_phrase();
            // ask user for a password to secure the wallet
            let pwd = prompt::create_password();
            // create wallet
            let mut w = Wallet::new(phrase)?;
            w.save_to(WalletFile {
                path: wallet_path,
                pwd,
            })?;
            w
        }
        Command::Interactive => {
            // load a wallet in interactive mode
            interactive::load_wallet(&wallet_path)?
        }
        _ => {
            // load wallet from file
            let pwd = prompt::request_auth("Please enter wallet password");
            Wallet::from_file(WalletFile {
                path: wallet_path,
                pwd,
            })?
        }
    };

    // set our status callback
    let status_cb = match cmd.is_headless() {
        true => status::headless,
        false => status::interactive,
    };

    // attempt to connect wallet
    #[cfg(windows)]
    let con = {
        let t = TransportTCP::new(&cfg.rusk.rusk_addr, &cfg.rusk.prover_addr);
        wallet.connect_with_status(t, status_cb).await
    };
    #[cfg(not(windows))]
    let con = {
        let ipc = cfg.rusk.ipc_method.as_str();
        match ipc {
            "uds" => {
                let t = TransportUDS::new(&cfg.rusk.rusk_addr);
                wallet.connect_with_status(t, status_cb).await
            }
            "tcp_ip" => {
                let t = TransportTCP::new(
                    &cfg.rusk.rusk_addr,
                    &cfg.rusk.prover_addr,
                );
                wallet.connect_with_status(t, status_cb).await
            }
            _ => panic!("IPC method not supported"),
        }
    };

    // check for connection errors
    if con.is_err() {
        warn!("Connection to Rusk Failed, some operations won't be available.");
    }

    // run command
    match cmd {
        Command::Interactive => {
            interactive::run_loop(&mut wallet, &cfg).await?;
        }
        _ => match cmd.run(&mut wallet).await? {
            RunResult::Balance(balance, spendable) => {
                if spendable {
                    println!("{}", balance.spendable);
                } else {
                    println!("{}", balance.value);
                }
            }
            RunResult::Address(addr) => {
                println!("{}", addr);
            }
            RunResult::Addresses(addrs) => {
                for a in addrs {
                    println!("{}", a);
                }
            }
            RunResult::Tx(hash) => {
                let txh = format!("{:x}", hash);
                if cfg.chain.wait_for_tx {
                    let gql =
                        GraphQL::new(&cfg.chain.gql_url, status::headless);
                    gql.wait_for(&txh).await?;
                }
                println!("{}", txh);
            }
            RunResult::StakeInfo(si, reward) => {
                if reward {
                    println!("{}", si.reward);
                } else {
                    match si.amount {
                        Some((value, ..)) => Dusk::from(value),
                        None => Dusk::from(0),
                    };
                }
            }
            RunResult::ExportedKeys(pub_key, key_pair) => {
                println!("{},{}", pub_key.display(), key_pair.display())
            }
        },
    }

    Ok(())
}
