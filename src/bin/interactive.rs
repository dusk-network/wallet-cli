// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use requestty::Question;

use super::command::Command;
use super::menu::Menu;
use super::prompt;
use super::settings::Settings;
use super::Wallet;

/// Run the interactive UX loop with a loaded wallet
pub async fn run_loop(
    wallet: &mut Wallet,
    settings: &Settings,
) -> anyhow::Result<()> {
    loop {
        // get balance for this address
        prompt::hide_cursor()?;
        let state = wallet.state().await?;
        prompt::hide_cursor()?;

        let addr = wallet.public_spend_keys().await?[0].clone();

        // display address information
        println!(
            "Balance:\n - Spendable: {}\n - Total: {}",
            state.maximum_transfer, state.balance
        );

        // operations menu
        let op = menu_op(addr, state.maximum_transfer, settings);

        // perform operations with this address
        match op? {
            AddrOp::Run(cmd) => {
                // request confirmation before running
                if prompt::confirm(&cmd)? {
                    // run command
                    prompt::hide_cursor()?;
                    let result = cmd.run(wallet, settings).await;
                    prompt::show_cursor()?;

                    // output results
                    match result {
                        Ok(res) => println!("\r{}", res),
                        Err(err) => println!("{}", err),
                    }
                }
            }
            AddrOp::Back => break,
        }
    }
    Ok(())
}

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
enum AddrOp {
    Run(Box<Command>),
    Back,
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
enum CommandMenuItem {
    Addresses,
    Balance,
    Transfer,
    Back,
}

/// Allows the user to choose the operation to perform for the
/// selected address
fn menu_op(
    address: String,
    balance: u64,
    _settings: &Settings,
) -> anyhow::Result<AddrOp> {
    use CommandMenuItem as CMI;

    let cmd_menu = Menu::new()
        .add(CMI::Addresses, "List addresses")
        .add(CMI::Balance, "Display balance info")
        .add(CMI::Transfer, "Transfer Dusk")
        .separator()
        .add(CMI::Back, "Back");

    let q = Question::select("theme")
        .message("What would you like to do?")
        .choices(cmd_menu.clone())
        .build();

    let answer = requestty::prompt_one(q)?;
    let cmd = cmd_menu.answer(&answer).to_owned();

    let res = match cmd {
        CMI::Addresses => AddrOp::Run(Box::new(Command::Addresses)),
        CMI::Balance => AddrOp::Run(Box::new(Command::Balance)),
        CMI::Transfer => AddrOp::Run(Box::new(Command::Transfer {
            sndr: Some(address),
            rcvr: prompt::request_rcvr_addr("recipient")?,
            amt: prompt::request_token_amt("transfer", balance)?,
            gas_limit: Some(prompt::request_gas_limit(10)?),
            gas_price: Some(prompt::request_gas_price()?),
        })),
        CMI::Back => AddrOp::Back,
    };
    Ok(res)
}
