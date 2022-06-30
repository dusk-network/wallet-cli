use wallet_lib::error::Error;

use std::path::Path;

use crate::config::Config;
use crate::prompt;
use wallet_lib::crypto::MnemSeed;
use wallet_lib::store::LocalStore;

use wallet_lib::handle::arg::CliCommand;
use wallet_lib::handle::arg::WalletArgs;

use clap::Parser;
use std::path::PathBuf;

use crate::wallet::CliWallet;
use wallet_lib::clients::{Prover, State};
use wallet_lib::dusk::Dusk;
use wallet_lib::gql::GraphQL;
use wallet_lib::rusk::RuskClient;

pub async fn exec() -> Result<(), Error> {
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
pub fn create(path: &Path, skip_recovery: bool) -> Result<LocalStore, Error> {
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
pub fn recover(path: &Path) -> Result<LocalStore, Error> {
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
pub fn open_interactive(cfg: &Config) -> Result<LocalStore, Error> {
    // find existing wallets
    let wallets = LocalStore::wallets_in(&cfg.wallet.data_dir)?;
    if !wallets.is_empty() {
        // let the user choose one
        let wallet = prompt::choose_wallet(&wallets);
        if let Some(p) = wallet {
            let pwd =
                prompt::request_auth("Please enter your wallet's password");
            let store = LocalStore::from_file(&p, pwd)?;
            Ok(store)
        } else {
            Ok(first_run(cfg)?)
        }
    } else {
        println!("No wallet files found at {}", cfg.wallet.data_dir.display());
        Ok(first_run(cfg)?)
    }
}

/// Welcome the user when no wallets are found
fn first_run(cfg: &Config) -> Result<LocalStore, Error> {
    // greet the user and ask for action
    let action = prompt::welcome();
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
pub fn exit() {
    std::process::exit(0);
}
