// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::io;

use crossterm::cursor::{Hide, Show};
use crossterm::ExecutableCommand;
use requestty::Question;

use super::command::Command;

/// Request a receiver address
pub fn request_rcvr_addr(addr_for: &str) -> anyhow::Result<String> {
    // let the user input the receiver address
    let q = Question::input("addr")
        .message(format!("Please enter the {} address:", addr_for))
        .build();

    let a = requestty::prompt_one(q)?;
    Ok(a.as_string().expect("answer to be a string").to_string())
}

/// Request amount of tokens
pub fn request_token_amt(action: &str, _balance: u64) -> anyhow::Result<u64> {
    let question = requestty::Question::float("amt")
        .message(format!("Introduce the amount of DUSK to {}:", action))
        .build();

    let a = requestty::prompt_one(question)?;
    Ok(a.as_float().expect("answer to be a float") as u64)
}

/// Request gas limit
pub fn request_gas_limit(default_gas_limit: u64) -> anyhow::Result<u64> {
    let question = requestty::Question::int("amt")
        .message("Introduce the gas limit for this transaction:")
        .default(default_gas_limit as i64)
        .build();

    let a = requestty::prompt_one(question)?;
    Ok(a.as_int().expect("answer to be an int") as u64)
}

/// Request gas price
pub fn request_gas_price() -> anyhow::Result<u64> {
    let question = requestty::Question::float("amt")
        .message("Introduce the gas price for this transaction:")
        .default(1.0)
        .build();

    let a = requestty::prompt_one(question)?;
    Ok(a.as_float().expect("answer to be a float") as u64)
}

/// Asks the user for confirmation
pub fn ask_confirm() -> anyhow::Result<bool> {
    let q = requestty::Question::confirm("confirm")
        .message("Transaction ready. Proceed?")
        .build();
    let a = requestty::prompt_one(q)?;
    Ok(a.as_bool().expect("answer to be a bool"))
}

pub fn confirm(cmd: &Command) -> anyhow::Result<bool> {
    match cmd {
        Command::Transfer {
            sndr,
            rcvr,
            amt,
            gas_limit,
            gas_price,
        } => {
            let sndr = sndr.as_ref().expect("sender to be a valid address");
            let gas_limit = gas_limit.expect("gas limit to be set");
            let gas_price = gas_price.expect("gas price to be set");
            let max_fee = gas_limit * gas_price;
            println!("   > Send from = {}", sndr);
            println!("   > Recipient = {}", rcvr);
            println!("   > Amount to transfer = {} DUSK", amt);
            println!("   > Max fee = {} DUSK", max_fee);
            ask_confirm()
        }
        _ => Ok(true),
    }
}

/// Shows the terminal cursor
pub fn show_cursor() -> anyhow::Result<()> {
    let mut stdout = io::stdout();
    stdout.execute(Show)?;
    Ok(())
}

/// Hides the terminal cursor
pub fn hide_cursor() -> anyhow::Result<()> {
    let mut stdout = io::stdout();
    stdout.execute(Hide)?;
    Ok(())
}
