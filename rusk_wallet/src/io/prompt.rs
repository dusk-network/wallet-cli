// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::io::stdout;
use std::path::Path;
use std::{env, str::FromStr};

use crossterm::{
    cursor::{Hide, Show},
    ExecutableCommand,
};

use bip39::{Language, Mnemonic};
use blake3::Hash;
use requestty::Question;

use dusk_wallet::{Address, Dusk, Lux, WalletPath};

use crate::Error;
use dusk_wallet::{
    DEFAULT_GAS_LIMIT, DEFAULT_GAS_PRICE, MAX_CONVERTIBLE, MIN_CONVERTIBLE,
    MIN_GAS_LIMIT,
};

/// Request the user to authenticate with a password
pub(crate) fn request_auth(msg: &str) -> Hash {
    let pwd = match env::var("RUSK_WALLET_PWD").ok() {
        Some(p) => p,

        None => {
            let q = Question::password("password")
                .message(format!("{}:", msg))
                .mask('*')
                .build();

            let a = requestty::prompt_one(q).expect("password");
            let p = a.as_string().unwrap();

            p.to_string()
        }
    };

    blake3::hash(pwd.as_bytes())
}

/// Request the user to create a wallet password
pub(crate) fn create_password() -> Hash {
    let pwd = match env::var("RUSK_WALLET_PWD") {
        Ok(p) => p,
        Err(_) => {
            let mut pwd = String::from("");

            let mut pwds_match = false;
            while !pwds_match {
                // enter password
                let q = Question::password("password")
                    .message("Enter a strong password for your wallet:")
                    .mask('*')
                    .build();
                let a = requestty::prompt_one(q).expect("password");
                let pwd1 = a.as_string().unwrap_or("").to_string();

                // confirm password
                let q = Question::password("password")
                    .message("Please confirm your password:")
                    .mask('*')
                    .build();
                let a =
                    requestty::prompt_one(q).expect("password confirmation");
                let pwd2 = a.as_string().unwrap_or("").to_string();

                // check match
                pwds_match = pwd1 == pwd2;
                if pwds_match {
                    pwd = pwd1.to_string()
                } else {
                    println!("Passwords don't match, please try again.");
                }
            }
            pwd
        }
    };

    let pwd = blake3::hash(pwd.as_bytes());
    pwd
}

/// Display the recovery phrase to the user and ask for confirmation
pub(crate) fn confirm_recovery_phrase<S>(phrase: &S)
where
    S: std::fmt::Display,
{
    // inform the user about the mnemonic phrase
    println!("The following phrase is essential for you to regain access to your wallet\nin case you lose access to this computer.");
    println!("Please print it or write it down and store it somewhere safe:");
    println!();
    println!("> {}", phrase);
    println!();

    // let the user confirm they have backed up their phrase
    loop {
        let q = requestty::Question::confirm("proceed")
            .message("Have you backed up your recovery phrase?")
            .build();

        let a = requestty::prompt_one(q).expect("confirmation");
        if a.as_bool().unwrap() {
            return;
        }
    }
}

/// Request the user to input the recovery phrase
pub(crate) fn request_recovery_phrase() -> String {
    // let the user input the recovery phrase
    let q = Question::input("phrase")
        .message("Please enter the recovery phrase:")
        .validate_on_key(|phrase, _| {
            Mnemonic::from_phrase(phrase, Language::English).is_ok()
        })
        .validate(|phrase, _| {
            if Mnemonic::from_phrase(phrase, Language::English).is_ok() {
                Ok(())
            } else {
                Err("Please enter a valid recovery phrase".to_string())
            }
        })
        .build();

    let a = requestty::prompt_one(q).expect("recovery phrase");
    let phrase = a.as_string().unwrap().to_string();
    phrase
}

/// Request a name for the wallet
pub(crate) fn request_wallet_name(dir: &Path) -> String {
    let q = Question::input("name")
        .message("Please enter a wallet name:")
        .default(WalletPath::default_name())
        .validate_on_key(|name, _| !WalletPath::exists(dir, name))
        .validate(|name, _| {
            if !WalletPath::exists(dir, name) {
                Ok(())
            } else {
                Err("A wallet with this name already exists".to_string())
            }
        })
        .build();

    let a = requestty::prompt_one(q).expect("wallet name");
    a.as_string().unwrap().to_string()
}

fn is_valid_dir(dir: &str) -> bool {
    let mut p = std::path::PathBuf::new();
    p.push(dir);
    p.is_dir()
}

/// Request a directory
pub(crate) fn request_dir(what_for: &str) -> std::path::PathBuf {
    let q = Question::input("name")
        .message(format!("Please enter a directory to {}:", what_for))
        .default(
            WalletPath::default_dir()
                .as_os_str()
                .to_str()
                .expect("default dir"),
        )
        .validate_on_key(|dir, _| is_valid_dir(dir))
        .validate(|dir, _| {
            if is_valid_dir(dir) {
                Ok(())
            } else {
                Err("Not a valid directory".to_string())
            }
        })
        .build();

    let a = requestty::prompt_one(q).expect("a directory");
    let mut p = std::path::PathBuf::new();
    p.push(a.as_string().unwrap());
    p
}

/// Asks the user for confirmation
pub(crate) fn ask_confirm() -> bool {
    let q = requestty::Question::confirm("confirm")
        .message("Transaction ready. Proceed?")
        .build();
    let a = requestty::prompt_one(q).expect("confirmation");
    a.as_bool().unwrap_or(false)
}

/// Request a receiver address
pub(crate) fn request_rcvr_addr(addr_for: &str) -> Address {
    // let the user input the receiver address
    let q = Question::input("addr")
        .message(format!("Please enter the {} address:", addr_for))
        .validate_on_key(|addr, _| Address::from_str(addr).is_ok())
        .validate(|addr, _| {
            if Address::from_str(addr).is_ok() {
                Ok(())
            } else {
                Err("Please introduce a valid DUSK address".to_string())
            }
        })
        .build();

    let a = requestty::prompt_one(q).expect("receiver address");
    Address::from_str(a.as_string().unwrap()).expect("correct address")
}

/// Checks for a valid DUSK denomination
fn check_valid_denom(value: f64, balance: Dusk) -> Result<(), String> {
    let value = Dusk::from(value);
    let min = MIN_CONVERTIBLE;
    let max = std::cmp::min(balance, MAX_CONVERTIBLE);
    match (min..=max).contains(&value) {
        true => Ok(()),
        false => {
            Err(format!("The amount has to be between {} and {}", min, max))
        }
    }
}

/// Request amount of tokens
pub(crate) fn request_token_amt(action: &str, balance: Dusk) -> Dusk {
    let question = requestty::Question::float("amt")
        .message(format!("Introduce the amount of DUSK to {}:", action))
        .default(MIN_CONVERTIBLE.into())
        .validate_on_key(|f, _| check_valid_denom(f, balance).is_ok())
        .validate(|f, _| check_valid_denom(f, balance))
        .build();

    let a = requestty::prompt_one(question).expect("token amount");
    a.as_float().unwrap().into()
}

/// Request gas limit
pub(crate) fn request_gas_limit() -> u64 {
    let question = requestty::Question::int("amt")
        .message("Introduce the gas limit for this transaction:")
        .default(DEFAULT_GAS_LIMIT as i64)
        .validate_on_key(|n, _| n > (MIN_GAS_LIMIT as i64))
        .validate(|n, _| {
            if n < MIN_GAS_LIMIT as i64 {
                Err("Gas limit too low".to_owned())
            } else {
                Ok(())
            }
        })
        .build();

    let a = requestty::prompt_one(question).expect("gas limit");
    a.as_int().unwrap() as u64
}

/// Request gas price
pub(crate) fn request_gas_price() -> Lux {
    let question = requestty::Question::float("amt")
        .message("Introduce the gas price for this transaction:")
        .default(Dusk::from(DEFAULT_GAS_PRICE).into())
        .validate_on_key(|f, _| check_valid_denom(f, MAX_CONVERTIBLE).is_ok())
        .validate(|f, _| check_valid_denom(f, MAX_CONVERTIBLE))
        .build();

    let a = requestty::prompt_one(question).expect("gas price");
    let price = Dusk::from(a.as_float().unwrap());
    *price
}

/// Request Dusk block explorer open
pub(crate) fn launch_explorer(url: String) -> bool {
    let q = requestty::Question::confirm("launch")
        .message("Launch block explorer?")
        .build();

    let a = requestty::prompt_one(q).expect("confirmation");
    let open = a.as_bool().unwrap_or(false);

    if open {
        match open::that(url) {
            Ok(()) => true,
            Err(_) => false,
        }
    } else {
        false
    }
}

/// Shows the terminal cursor
pub(crate) fn show_cursor() -> Result<(), Error> {
    let mut stdout = stdout();
    stdout.execute(Show)?;
    Ok(())
}

/// Hides the terminal cursor
pub(crate) fn hide_cursor() -> Result<(), Error> {
    let mut stdout = stdout();
    stdout.execute(Hide)?;
    Ok(())
}
