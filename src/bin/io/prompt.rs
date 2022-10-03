// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::io::stdout;
use std::path::PathBuf;
use std::str::FromStr;

use crossterm::{
    cursor::{Hide, Show},
    ExecutableCommand,
};

use anyhow::Result;
use bip39::{ErrorKind, Language, Mnemonic};
use blake3::Hash;
use dusk_wallet::Error;
use requestty::{OnEsc, Question};

use dusk_wallet::{Address, Dusk, Lux};

use dusk_wallet::gas;
use dusk_wallet::{MAX_CONVERTIBLE, MIN_CONVERTIBLE};

/// Request the user to authenticate with a password
pub(crate) fn request_auth(msg: &str, password: &Option<String>) -> Hash {
    let pwd = match password.as_ref() {
        Some(p) => p.to_string(),

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
pub(crate) fn create_password(password: &Option<String>) -> Hash {
    let pwd = match password.as_ref() {
        Some(p) => p.to_string(),
        None => {
            let mut pwd = String::from("");

            let mut pwds_match = false;
            while !pwds_match {
                // enter password
                let q = Question::password("password")
                    .message("Enter the password for the wallet:")
                    .mask('*')
                    .build();
                let a = requestty::prompt_one(q).expect("password");
                let pwd1 = a.as_string().unwrap_or("").to_string();

                // confirm password
                let q = Question::password("password")
                    .message("Please confirm the password:")
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
pub(crate) fn request_recovery_phrase() -> anyhow::Result<String> {
    // let the user input the recovery phrase
    let mut attempt = 1;
    loop {
        let q = Question::input("phrase")
            .message("Please enter the recovery phrase:")
            .build();

        let a = requestty::prompt_one(q).expect("recovery phrase");
        let phrase = a.as_string().unwrap_or_default();

        match Mnemonic::from_phrase(phrase, Language::English) {
            Ok(phrase) => break Ok(phrase.to_string()),

            Err(err) if attempt > 2 => match err.downcast_ref::<ErrorKind>() {
                Some(ErrorKind::InvalidWord) => {
                    return Err(Error::AttemptsExhausted)?
                }
                _ => return Err(err),
            },
            Err(_) => {
                println!("Invalid recovery phrase please try again");
                attempt += 1;
            }
        }
    }
}

fn is_valid_dir(dir: &str) -> bool {
    let mut p = std::path::PathBuf::new();
    p.push(dir);
    p.is_dir()
}

/// Request a directory
pub(crate) fn request_dir(
    what_for: &str,
    profile: PathBuf,
) -> Result<std::path::PathBuf> {
    let q = Question::input("name")
        .message(format!("Please enter a directory to {}:", what_for))
        .on_esc(OnEsc::Terminate)
        .default(profile.as_os_str().to_str().expect("default dir"))
        .validate_on_key(|dir, _| is_valid_dir(dir))
        .validate(|dir, _| {
            if is_valid_dir(dir) {
                Ok(())
            } else {
                Err("Not a valid directory".to_string())
            }
        })
        .build();

    let a = requestty::prompt_one(q)?;
    let mut p = std::path::PathBuf::new();
    p.push(a.as_string().unwrap());
    Ok(p)
}

/// Asks the user for confirmation
pub(crate) fn ask_confirm() -> bool {
    let question = requestty::Question::confirm("confirm")
        .message("Transaction ready. Proceed?")
        .on_esc(OnEsc::Terminate)
        .build();

    requestty::prompt_one(question)
        .map(|answer| answer.as_bool())
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Request a receiver address
pub(crate) fn request_rcvr_addr(addr_for: &str) -> anyhow::Result<Address> {
    // let the user input the receiver address
    let q = Question::input("addr")
        .message(format!("Please enter the {} address:", addr_for))
        .on_esc(OnEsc::Terminate)
        .validate_on_key(|addr, _| Address::from_str(addr).is_ok())
        .validate(|addr, _| {
            if Address::from_str(addr).is_ok() {
                Ok(())
            } else {
                Err("Please introduce a valid DUSK address".to_string())
            }
        })
        .build();

    let a = requestty::prompt_one(q)?;
    Ok(Address::from_str(a.as_string().unwrap())?)
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
pub(crate) fn request_token_amt(
    action: &str,
    balance: Dusk,
) -> anyhow::Result<Dusk> {
    let question = requestty::Question::float("amt")
        .message(format!("Introduce the amount of DUSK to {}:", action))
        .on_esc(OnEsc::Terminate)
        .default(MIN_CONVERTIBLE.into())
        .validate_on_key(|f, _| check_valid_denom(f, balance).is_ok())
        .validate(|f, _| check_valid_denom(f, balance))
        .build();

    let a = requestty::prompt_one(question)?;
    Ok(a.as_float().unwrap().into())
}

/// Request gas limit
pub(crate) fn request_gas_limit() -> anyhow::Result<u64> {
    let question = requestty::Question::int("amt")
        .message("Introduce the gas limit for this transaction:")
        .on_esc(OnEsc::Terminate)
        .default(gas::DEFAULT_LIMIT as i64)
        .validate_on_key(|n, _| n > (gas::MIN_LIMIT as i64))
        .validate(|n, _| {
            if n < gas::MIN_LIMIT as i64 {
                Err("Gas limit too low".to_owned())
            } else {
                Ok(())
            }
        })
        .build();

    let a = requestty::prompt_one(question)?;
    Ok(a.as_int().unwrap() as u64)
}

/// Request gas price
pub(crate) fn request_gas_price() -> anyhow::Result<Lux> {
    let question = requestty::Question::float("amt")
        .message("Introduce the gas price for this transaction:")
        .on_esc(OnEsc::Terminate)
        .default(Dusk::from(gas::DEFAULT_PRICE).into())
        .validate_on_key(|f, _| check_valid_denom(f, MAX_CONVERTIBLE).is_ok())
        .validate(|f, _| check_valid_denom(f, MAX_CONVERTIBLE))
        .build();

    let a = requestty::prompt_one(question)?;
    let price = Dusk::from(a.as_float().unwrap());
    Ok(*price)
}

/// Request Dusk block explorer open
pub(crate) fn launch_explorer(url: String) -> Result<()> {
    let q = requestty::Question::confirm("launch")
        .message("Launch block explorer?")
        .on_esc(OnEsc::Terminate)
        .default(false)
        .build();

    let a = requestty::prompt_one(q)?;
    let open = a.as_bool().unwrap_or_default();
    if open {
        open::that(url)?;
    }
    Ok(())
}

/// Shows the terminal cursor
pub(crate) fn show_cursor() -> anyhow::Result<()> {
    let mut stdout = stdout();
    stdout.execute(Show)?;
    Ok(())
}

/// Hides the terminal cursor
pub(crate) fn hide_cursor() -> anyhow::Result<()> {
    let mut stdout = stdout();
    stdout.execute(Hide)?;
    Ok(())
}
