// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use bip39::{Language, Mnemonic, MnemonicType};
use dusk_wallet::gas;
use dusk_wallet::{Address, Dusk, Wallet, WalletPath};
use requestty::Question;

use crate::command::DEFAULT_STAKE_GAS_LIMIT;
use crate::io;
use crate::io::GraphQL;
use crate::prompt;
use crate::settings::Settings;
use crate::Menu;
use crate::WalletFile;
use crate::{Command, RunResult};
use dusk_wallet::Error;
use std::path::PathBuf;

/// Run the interactive UX loop with a loaded wallet
pub(crate) async fn run_loop(
    wallet: &mut Wallet<WalletFile>,
    settings: &Settings,
) -> anyhow::Result<()> {
    loop {
        // let the user choose (or create) an address
        let addr = match menu_addr(wallet)? {
            AddrSelect::Address(addr) => *addr,
            AddrSelect::NewAddress => {
                let addr = wallet.new_address().clone();
                wallet.save()?;
                addr
            }
            AddrSelect::Exit => std::process::exit(0),
        };

        loop {
            // request operation to perform
            let op = if wallet.is_online() {
                // get balance for this address
                prompt::hide_cursor()?;
                let balance = wallet.get_balance(&addr).await?;
                prompt::hide_cursor()?;

                // display address information
                println!("\rAddress: {}", addr);
                println!(
                    "Balance:\n - Spendable: {}\n - Total: {}",
                    Dusk::from(balance.spendable),
                    Dusk::from(balance.value)
                );

                // operations menu
                menu_op(addr.clone(), balance.spendable.into(), settings)
            } else {
                // display address information
                println!("\rAddress: {}", addr);
                println!("Balance:\n - Spendable: [n/a]\n - Total: [n/a]");
                menu_op_offline(addr.clone(), settings)
            };

            // perform operations with this address
            match op? {
                AddrOp::Run(cmd) => {
                    // request confirmation before running
                    if confirm(&cmd)? {
                        // run command
                        prompt::hide_cursor()?;
                        let result = cmd.run(wallet, settings).await;
                        prompt::show_cursor()?;
                        // output results
                        match result {
                            Ok(res) => {
                                println!("\r{}", res);
                                if let RunResult::Tx(hash) = res {
                                    let txh = format!("{:x}", hash);

                                    // Wait for transaction confirmation from
                                    // network
                                    let gql = GraphQL::new(
                                        &settings.graphql.to_string(),
                                        io::status::interactive,
                                    );
                                    gql.wait_for(&txh).await?;

                                    if let Some(explorer) = &settings.explorer {
                                        let base_url = explorer.to_string();

                                        let url =
                                            format!("{}{}", base_url, txh);
                                        println!("> URL: {}", url);
                                        prompt::launch_explorer(url)?;
                                    }
                                }
                            }

                            Err(err) => println!("{}", err),
                        }
                    }
                }
                AddrOp::Back => break,
            }
        }
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
enum AddrSelect {
    Address(Box<Address>),
    NewAddress,
    Exit,
}

/// Allows the user to choose an address from the selected wallet
/// to start performing operations.
fn menu_addr(wallet: &Wallet<WalletFile>) -> anyhow::Result<AddrSelect> {
    let mut address_menu = Menu::title("Addresses");
    for addr in wallet.addresses() {
        let preview = addr.preview();
        address_menu = address_menu
            .add(AddrSelect::Address(Box::new(addr.clone())), preview);
    }

    let action_menu = Menu::new()
        .separator()
        .add(AddrSelect::NewAddress, "New address")
        .separator()
        .add(AddrSelect::Exit, "Exit");

    let menu = address_menu.extend(action_menu);
    let questions = Question::select("theme")
        .message("Please select an address")
        .choices(menu.clone())
        .build();

    let answer = requestty::prompt_one(questions)?;
    Ok(menu.answer(&answer).to_owned())
}

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
enum AddrOp {
    Run(Box<Command>),
    Back,
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
enum CommandMenuItem {
    Transfer,
    Stake,
    StakeInfo,
    Unstake,
    Withdraw,
    Export,
    Back,
}

/// Allows the user to choose the operation to perform for the
/// selected address
fn menu_op(
    addr: Address,
    balance: Dusk,
    settings: &Settings,
) -> anyhow::Result<AddrOp> {
    use CommandMenuItem as CMI;

    let cmd_menu = Menu::new()
        .add(CMI::Transfer, "Transfer Dusk")
        .add(CMI::Stake, "Stake Dusk")
        .add(CMI::StakeInfo, "Check existing stake")
        .add(CMI::Unstake, "Unstake Dusk")
        .add(CMI::Withdraw, "Withdraw staking reward")
        .add(CMI::Export, "Export provisioner key-pair")
        .separator()
        .add(CMI::Back, "Back");

    let q = Question::select("theme")
        .message("What would you like to do?")
        .choices(cmd_menu.clone())
        .build();

    let answer = requestty::prompt_one(q)?;
    let cmd = cmd_menu.answer(&answer).to_owned();

    let res = match cmd {
        CMI::Transfer => AddrOp::Run(Box::new(Command::Transfer {
            sndr: Some(addr),
            rcvr: prompt::request_rcvr_addr("recipient")?,
            amt: prompt::request_token_amt("transfer", balance)?,
            gas_limit: Some(prompt::request_gas_limit(gas::DEFAULT_LIMIT)?),
            gas_price: Some(prompt::request_gas_price()?),
        })),
        CMI::Stake => AddrOp::Run(Box::new(Command::Stake {
            addr: Some(addr),
            amt: prompt::request_token_amt("stake", balance)?,
            gas_limit: Some(prompt::request_gas_limit(
                DEFAULT_STAKE_GAS_LIMIT,
            )?),
            gas_price: Some(prompt::request_gas_price()?),
        })),
        CMI::StakeInfo => AddrOp::Run(Box::new(Command::StakeInfo {
            addr: Some(addr),
            reward: false,
        })),
        CMI::Unstake => AddrOp::Run(Box::new(Command::Unstake {
            addr: Some(addr),
            gas_limit: Some(prompt::request_gas_limit(
                DEFAULT_STAKE_GAS_LIMIT,
            )?),
            gas_price: Some(prompt::request_gas_price()?),
        })),
        CMI::Withdraw => AddrOp::Run(Box::new(Command::Withdraw {
            addr: Some(addr),
            gas_limit: Some(prompt::request_gas_limit(
                DEFAULT_STAKE_GAS_LIMIT,
            )?),
            gas_price: Some(prompt::request_gas_price()?),
        })),
        CMI::Export => AddrOp::Run(Box::new(Command::Export {
            addr: Some(addr),
            dir: prompt::request_dir("export keys", settings.profile.clone())?,
        })),
        CMI::Back => AddrOp::Back,
    };
    Ok(res)
}

/// Allows the user to choose the operation to perform for the
/// selected address while in offline mode
fn menu_op_offline(
    addr: Address,
    settings: &Settings,
) -> anyhow::Result<AddrOp> {
    use CommandMenuItem as CMI;

    let cmd_menu = Menu::new()
        .separator()
        .add(CMI::Export, "Export provisioner key-pair")
        .separator()
        .add(CMI::Back, "Back");

    let q = Question::select("theme")
        .message("What would you like to do?")
        .choices(cmd_menu.clone())
        .build();

    let answer = requestty::prompt_one(q)?;
    let cmd = cmd_menu.answer(&answer).to_owned();

    let res = match cmd {
        CMI::Export => AddrOp::Run(Box::new(Command::Export {
            addr: Some(addr),
            dir: prompt::request_dir("export keys", settings.profile.clone())?,
        })),
        CMI::Back => AddrOp::Back,
        _ => unreachable!(),
    };
    Ok(res)
}

/// Allows the user to load a wallet interactively
pub(crate) fn load_wallet(
    wallet_path: &WalletPath,
    settings: &Settings,
) -> anyhow::Result<Wallet<WalletFile>> {
    let wallet_found = wallet_path
        .inner()
        .exists()
        .then(|| wallet_path.inner().clone());

    let password = &settings.password;

    // display main menu
    let wallet = match menu_wallet(wallet_found)? {
        MainMenu::Load(path) => {
            let mut attempt = 1;
            loop {
                let pwd = prompt::request_auth(
                    "Please enter your wallet password",
                    password,
                )?;
                match Wallet::from_file(WalletFile {
                    path: path.clone(),
                    pwd,
                }) {
                    Ok(wallet) => break wallet,
                    Err(_) if attempt > 2 => {
                        return Err(Error::AttemptsExhausted)?;
                    }
                    Err(_) => {
                        println!("Invalid password, please try again");
                        attempt += 1;
                    }
                }
            }
        }
        MainMenu::Create => {
            // create a new randomly generated mnemonic phrase
            let mnemonic =
                Mnemonic::new(MnemonicType::Words12, Language::English);
            // ask user for a password to secure the wallet
            let pwd = prompt::create_password(password)?;
            // display the recovery phrase
            prompt::confirm_recovery_phrase(&mnemonic)?;
            // create and store the wallet
            let mut w = Wallet::new(mnemonic)?;
            let path = wallet_path.clone();
            w.save_to(WalletFile { path, pwd })?;
            w
        }
        MainMenu::Recover => {
            // ask user for 12-word recovery phrase
            let phrase = prompt::request_recovery_phrase()?;
            // ask user for a password to secure the wallet
            let pwd = prompt::create_password(&None)?;
            // create and store the recovered wallet
            let mut w = Wallet::new(phrase)?;
            let path = wallet_path.clone();
            w.save_to(WalletFile { path, pwd })?;
            w
        }
        MainMenu::Exit => std::process::exit(0),
    };

    Ok(wallet)
}

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
enum MainMenu {
    Load(WalletPath),
    Create,
    Recover,
    Exit,
}

/// Allows the user to load an existing wallet, recover a lost one
/// or create a new one.
fn menu_wallet(wallet_found: Option<PathBuf>) -> anyhow::Result<MainMenu> {
    // create the wallet menu
    let mut menu = Menu::new();

    if let Some(wallet_path) = wallet_found {
        menu = menu
            .separator()
            .add(
                MainMenu::Load(WalletPath::from(wallet_path)),
                "Access your wallet",
            )
            .separator()
            .add(MainMenu::Create, "Replace your wallet with a new one")
            .add(
                MainMenu::Recover,
                "Replace your wallet with a lost one using the recovery phrase",
            )
    } else {
        menu = menu.add(MainMenu::Create, "Create a new wallet").add(
            MainMenu::Recover,
            "Access a lost wallet using the recovery phrase",
        )
    }

    // create the action menu
    menu = menu.separator().add(MainMenu::Exit, "Exit");

    // let the user choose an option
    let questions = Question::select("theme")
        .message("What would you like to do?")
        .choices(menu.clone())
        .build();

    let answer = requestty::prompt_one(questions)?;
    Ok(menu.answer(&answer).to_owned())
}

/// Request user confirmation for a transfer transaction
fn confirm(cmd: &Command) -> anyhow::Result<bool> {
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
            println!("   > Send from = {}", sndr.preview());
            println!("   > Recipient = {}", rcvr.preview());
            println!("   > Amount to transfer = {} DUSK", amt);
            println!("   > Max fee = {} DUSK", Dusk::from(max_fee));
            prompt::ask_confirm()
        }
        Command::Stake {
            addr,
            amt,
            gas_limit,
            gas_price,
        } => {
            let addr = addr.as_ref().expect("address to be valid");
            let gas_limit = gas_limit.expect("gas limit to be set");
            let gas_price = gas_price.expect("gas price to be set");
            let max_fee = gas_limit * gas_price;
            println!("   > Stake from {}", addr.preview());
            println!("   > Amount to stake = {} DUSK", amt);
            println!("   > Max fee = {} DUSK", Dusk::from(max_fee));
            prompt::ask_confirm()
        }
        Command::Unstake {
            addr,
            gas_limit,
            gas_price,
        } => {
            let addr = addr.as_ref().expect("address to be valid");
            let gas_limit = gas_limit.expect("gas limit to be set");
            let gas_price = gas_price.expect("gas price to be set");
            let max_fee = gas_limit * gas_price;
            println!("   > Unstake from {}", addr.preview());
            println!("   > Max fee = {} DUSK", Dusk::from(max_fee));
            prompt::ask_confirm()
        }
        Command::Withdraw {
            addr,
            gas_limit,
            gas_price,
        } => {
            let addr = addr.as_ref().expect("address to be valid");
            let gas_limit = gas_limit.expect("gas limit to be set");
            let gas_price = gas_price.expect("gas price to be set");
            let max_fee = gas_limit * gas_price;
            println!("   > Reward from {}", addr.preview());
            println!("   > Max fee = {} DUSK", Dusk::from(max_fee));
            prompt::ask_confirm()
        }
        _ => Ok(true),
    }
}
