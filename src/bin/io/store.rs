// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::config::Config;
use crate::io::prompt;
use wallet_lib::crypto::MnemSeed;
use wallet_lib::LocalStore;

use std::path::Path;
use wallet_lib::error::Error;
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
