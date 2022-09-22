// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod command;
mod config;
mod interactive;
mod io;
mod menu;
mod settings;

pub(crate) use command::{Command, RunResult};
pub(crate) use menu::Menu;

use clap::Parser;
use std::fs;
use tracing::{warn, Level};

use bip39::{Language, Mnemonic, MnemonicType};
use blake3::Hash;

use crate::settings::{LogFormat, Settings};

#[cfg(not(windows))]
use dusk_wallet::TransportUDS;

use dusk_wallet::{Dusk, SecureWalletFile, TransportTCP, Wallet, WalletPath};

use config::{Config, TransportMethod};
use io::{prompt, status};
use io::{GraphQL, WalletArgs};

#[derive(Debug, Clone)]
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
async fn main() -> anyhow::Result<()> {
    if let Err(err) = exec().await {
        // display the error message (if any)
        eprintln!("{}", err);
        // give cursor back to the user
        io::prompt::show_cursor()?;
    }
    Ok(())
}

async fn connect<F>(
    mut wallet: Wallet<F>,
    settings: &Settings,
    status: fn(&str),
) -> Wallet<F>
where
    F: SecureWalletFile + std::fmt::Debug,
{
    let con = match (&settings.state.method(), &settings.prover.method()) {
        (TransportMethod::Tcp, TransportMethod::Tcp) => {
            wallet
                .connect_with_status(
                    TransportTCP::new(&settings.state, &settings.prover),
                    status,
                )
                .await
        }
        #[cfg(not(windows))]
        (TransportMethod::Uds, _) => {
            wallet
                .connect_with_status(TransportUDS::new(&settings.state), status)
                .await
        }

        (_, _) => panic!("IPC method not supported"),
    };

    // check for connection errors
    if con.is_err() {
        warn!("Connection to Rusk Failed, some operations won't be available.");
    }

    wallet
}

async fn exec() -> anyhow::Result<()> {
    // parse user args
    let args = WalletArgs::parse();
    // get the subcommand, if any
    let cmd = args.command.clone();

    // set symbols to ASCII for Windows terminal compatibility
    #[cfg(windows)]
    requestty::symbols::set(requestty::symbols::ASCII);

    // Get the initial settings from the args
    let settings = Settings::args(args);

    // Obtain the profile dir from the settings
    let profile_folder = settings.profile().clone();

    fs::create_dir_all(&profile_folder)?;

    // prepare wallet path
    let wallet_path = WalletPath::from(profile_folder.join("wallet.dat"));

    // load configuration (or use default)
    let cfg = Config::load(&profile_folder)?;

    // Finally complete the settings by set the network
    let settings = settings.network(cfg.network);

    // set cache directory straight away
    WalletPath::set_cache_dir(&profile_folder)?;

    // generate a subscriber with the desired log level
    //
    // TODO: we should have the logger instantiate sooner, otherwise we cannot
    // catch errors that are happened before its instantiation.
    //
    // Therefore, the logger details such as `type` and `level` cannot be part
    // of the configuration, since it won't catch any configuration error
    // otherwise.
    //
    // See: <https://github.com/dusk-network/wallet-cli/issues/73>
    //
    let level = &settings.logging.level;
    let level: Level = level.into();
    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_max_level(level)
        .with_writer(std::io::stderr);

    // set the subscriber as global
    match settings.logging.format {
        LogFormat::Json => {
            let subscriber = subscriber.json().flatten_event(true).finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
        LogFormat::Plain => {
            let subscriber = subscriber.with_ansi(false).finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
        LogFormat::Coloured => {
            let subscriber = subscriber.finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
    };

    let is_headless = cmd.is_some();

    let password = &settings.password;

    match cmd {
        Some(ref cmd) if cmd == &Command::Settings => {
            println!("{}", &settings);
            return Ok(());
        }
        _ => {}
    };

    // get our wallet ready
    let mut wallet: Wallet<WalletFile> = match cmd {
        Some(ref cmd) => match cmd {
            Command::Create { skip_recovery } => {
                // create a new randomly generated mnemonic phrase
                let mnemonic =
                    Mnemonic::new(MnemonicType::Words12, Language::English);
                // ask user for a password to secure the wallet
                let pwd = prompt::create_password(password);
                // skip phrase confirmation if explicitly
                if !skip_recovery {
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
            Command::Restore { file } => {
                let (mut w, pwd) = match file {
                    Some(file) => {
                        let pwd = prompt::request_auth(
                            "Please enter wallet password",
                            password,
                        );

                        let w = Wallet::from_file(WalletFile {
                            path: file.clone(),
                            pwd,
                        })?;
                        (w, pwd)
                    }
                    None => {
                        // ask user for 12-word recovery phrase
                        let phrase = prompt::request_recovery_phrase();
                        // ask user for a password to secure the wallet
                        let pwd = prompt::create_password(password);
                        // create wallet
                        let w = Wallet::new(phrase)?;

                        (w, pwd)
                    }
                };

                w.save_to(WalletFile {
                    path: wallet_path,
                    pwd,
                })?;
                w
            }

            _ => {
                // load wallet from file
                let pwd = prompt::request_auth(
                    "Please enter wallet password",
                    password,
                );
                Wallet::from_file(WalletFile {
                    path: wallet_path,
                    pwd,
                })?
            }
        },
        None => {
            // load a wallet in interactive mode
            interactive::load_wallet(&wallet_path, &settings)?
        }
    };

    // set our status callback
    let status_cb = match is_headless {
        true => status::headless,
        false => status::interactive,
    };

    wallet = connect(wallet, &settings, status_cb).await;

    // run command
    match cmd {
        Some(cmd) => match cmd.run(&mut wallet, &settings).await? {
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

                // Wait for transaction confirmation from network
                let gql = GraphQL::new(
                    &settings.graphql.to_string(),
                    status::headless,
                );
                gql.wait_for(&txh).await?;

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
            RunResult::Settings() => {}
            RunResult::Create() | RunResult::Restore() => {}
        },
        None => {
            interactive::run_loop(&mut wallet, &settings).await?;
        }
    }

    Ok(())
}
