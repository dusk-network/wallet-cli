// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use bip39::{Language, Mnemonic, MnemonicType};
use dusk_wallet::{Address, Dusk, Wallet, WalletPath};
use requestty::Question;

use crate::io;
use crate::io::Config;
use crate::io::GraphQL;
use crate::prompt;
use crate::Error;
use crate::Menu;
use crate::WalletFile;
use crate::{Command, RunResult};

/// Run the interactive UX loop with a loaded wallet
pub(crate) async fn run_loop(
    wallet: &mut Wallet<WalletFile>,
    cfg: &Config,
) -> Result<(), Error> {
    loop {
        // let the user choose (or create) an address
        let addr = match menu_addr(wallet) {
            AddrSelect::Address(addr) => *addr,
            AddrSelect::NewAddress => {
                let addr = wallet.new_address();
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
                menu_op(addr.clone(), balance.spendable.into())
            } else {
                // display address information
                println!("\rAddress: {}", addr);
                println!("Balance:\n - Spendable: [n/a]\n - Total: [n/a]");
                menu_op_offline(addr.clone())
            };

            // perform operations with this address
            match op {
                AddrOp::Run(cmd) => {
                    // request confirmation before running
                    if confirm(&cmd) {
                        // run command
                        prompt::hide_cursor()?;
                        let result = cmd.run(wallet).await;
                        prompt::show_cursor()?;

                        // output results
                        match result {
                            Ok(res) => {
                                println!("\r{}", res);
                                if let RunResult::Tx(hash) = res {
                                    let txh = format!("{:x}", hash);
                                    if cfg.chain.wait_for_tx {
                                        let gql = GraphQL::new(
                                            &cfg.chain.gql_url,
                                            io::status::interactive,
                                        );
                                        gql.wait_for(&txh).await?;
                                    }
                                    if let Some(base_url) = &cfg.explorer.tx_url
                                    {
                                        let url =
                                            format!("{}{}", base_url, txh);
                                        println!("> URL: {}", url);
                                        prompt::launch_explorer(url);
                                    }
                                }
                            }
                            Err(err) => println!("{}", err),
                        }
                    }
                }
                AddrOp::Return => break,
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
fn menu_addr(wallet: &Wallet<WalletFile>) -> AddrSelect {
    let mut address_menu = Menu::title("Use an existing address:");
    for addr in wallet.addresses() {
        let preview = addr.preview();
        address_menu =
            address_menu.add(AddrSelect::Address(Box::new(addr)), preview);
    }

    let action_menu = Menu::title("Other actions...")
        .add(AddrSelect::NewAddress, "New address")
        .separator()
        .add(AddrSelect::Exit, "Exit");

    let menu = address_menu.extend(action_menu);
    let questions = Question::select("theme")
        .message("Please select an address")
        .choices(menu.clone())
        .build();

    let answer = requestty::prompt_one(questions).expect("An answer");
    menu.answer(&answer).to_owned()
}

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
enum AddrOp {
    Run(Box<Command>),
    Return,
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
enum CommandMenuItem {
    Transfer,
    Stake,
    StakeInfo,
    Unstake,
    Withdraw,
    Export,
    Return,
}

/// Allows the user to chose the operation to perform for the
/// selected address
fn menu_op(addr: Address, balance: Dusk) -> AddrOp {
    use CommandMenuItem as CMI;

    let cmd_menu = Menu::title("Operations:")
        .add(CMI::Transfer, "Transfer Dusk")
        .add(CMI::Stake, "Stake Dusk")
        .add(CMI::StakeInfo, "Check existing stake")
        .add(CMI::Unstake, "Unstake Dusk")
        .add(CMI::Withdraw, "Withdraw staking reward")
        .add(CMI::Export, "Export provisioner key-pair")
        .separator()
        .add(CMI::Return, "Return to wallet dashboard");

    let q = Question::select("theme")
        .message("What would you like to do?")
        .choices(cmd_menu.clone())
        .build();

    let answer = requestty::prompt_one(q).expect("An answer");
    let cmd = cmd_menu.answer(&answer).to_owned();

    match cmd {
        CMI::Transfer => AddrOp::Run(Box::new(Command::Transfer {
            sndr: Some(addr),
            rcvr: prompt::request_rcvr_addr("recipient"),
            amt: prompt::request_token_amt("transfer", balance),
            gas_limit: Some(prompt::request_gas_limit()),
            gas_price: Some(prompt::request_gas_price()),
        })),
        CMI::Stake => AddrOp::Run(Box::new(Command::Stake {
            addr: Some(addr),
            amt: prompt::request_token_amt("stake", balance),
            gas_limit: Some(prompt::request_gas_limit()),
            gas_price: Some(prompt::request_gas_price()),
        })),
        CMI::StakeInfo => AddrOp::Run(Box::new(Command::StakeInfo {
            addr: Some(addr),
            reward: false,
        })),
        CMI::Unstake => AddrOp::Run(Box::new(Command::Unstake {
            addr: Some(addr),
            gas_limit: Some(prompt::request_gas_limit()),
            gas_price: Some(prompt::request_gas_price()),
        })),
        CMI::Withdraw => AddrOp::Run(Box::new(Command::Withdraw {
            addr: Some(addr),
            refund_addr: prompt::request_rcvr_addr("refund"),
            gas_limit: Some(prompt::request_gas_limit()),
            gas_price: Some(prompt::request_gas_price()),
        })),
        CMI::Export => AddrOp::Run(Box::new(Command::Export {
            addr: Some(addr),
            dir: prompt::request_dir("export keys"),
        })),
        CMI::Return => AddrOp::Return,
    }
}

/// Allows the user to chose the operation to perform for the
/// selected address while in offline mode
fn menu_op_offline(addr: Address) -> AddrOp {
    use CommandMenuItem as CMI;

    let cmd_menu = Menu::title("Operations:")
        .add(CMI::Export, "Export provisioner key-pair")
        .separator()
        .add(CMI::Return, "Return to wallet dashboard");

    let q = Question::select("theme")
        .message("What would you like to do?")
        .choices(cmd_menu.clone())
        .build();

    let answer = requestty::prompt_one(q).expect("An answer");
    let cmd = cmd_menu.answer(&answer).to_owned();

    match cmd {
        CMI::Export => AddrOp::Run(Box::new(Command::Export {
            addr: Some(addr),
            dir: prompt::request_dir("export keys"),
        })),
        CMI::Return => AddrOp::Return,
        _ => unreachable!(),
    }
}

/// Allows the user to load a wallet interactively
pub(crate) fn load_wallet(
    wallet_path: &WalletPath,
) -> Result<Wallet<WalletFile>, Error> {
    // find wallets in the specified data directory
    let wallet_dir = wallet_path.dir().unwrap_or_else(WalletPath::default_dir);
    let wallets_found = WalletPath::wallets_in(&wallet_dir)?;

    // display main menu
    let wallet = match menu_wallet(&wallets_found) {
        MainMenu::Load(path) => {
            let pwd =
                prompt::request_auth("Please enter you wallet's password");
            Wallet::from_file(WalletFile { path, pwd })?
        }
        MainMenu::Create => {
            // create a new randomly generated mnemonic phrase
            let mnemonic =
                Mnemonic::new(MnemonicType::Words12, Language::English);
            // let the user give this wallet a name
            let name = prompt::request_wallet_name(&wallet_dir);
            // ask user for a password to secure the wallet
            let pwd = prompt::create_password();
            // display the recovery phrase
            prompt::confirm_recovery_phrase(&mnemonic);
            // create and store the wallet
            let mut w = Wallet::new(mnemonic)?;
            let path = WalletPath::new(&wallet_dir, name);
            w.save_to(WalletFile { path, pwd })?;
            w
        }
        MainMenu::Recover => {
            // ask user for 12-word recovery phrase
            let phrase = prompt::request_recovery_phrase();
            // let the user give this wallet a name
            let name = prompt::request_wallet_name(&wallet_dir);
            // ask user for a password to secure the wallet
            let pwd = prompt::create_password();
            // create and store the recovered wallet
            let mut w = Wallet::new(phrase)?;
            let path = WalletPath::new(&wallet_dir, name);
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
fn menu_wallet(wallets: &Vec<WalletPath>) -> MainMenu {
    // create the wallet menu
    let mut wallet_menu = Menu::title("Access an existing wallet:");
    for wallet in wallets {
        let name = wallet.name().unwrap_or_else(|| "[no name]".to_string());
        wallet_menu = wallet_menu.add(MainMenu::Load(wallet.clone()), name);
    }

    // create the action menu
    let action_menu = Menu::title("Other actions...")
        .add(
            MainMenu::Create,
            "Create a new wallet and store it in this computer",
        )
        .add(
            MainMenu::Recover,
            "Access a lost wallet using the recovery phrase",
        )
        .separator()
        .add(MainMenu::Exit, "Exit");

    // don't display wallet menu if there are no wallets
    let menu = if !wallets.is_empty() {
        wallet_menu.extend(action_menu)
    } else {
        action_menu
    };

    // let the user choose an option
    let questions = Question::select("theme")
        .message("What would you like to do?")
        .choices(menu.clone())
        .build();

    let answer = requestty::prompt_one(questions).expect("An answer");
    menu.answer(&answer).to_owned()
}

/// Request user confirmation for a trasfer transaction
fn confirm(cmd: &Command) -> bool {
    match cmd {
        Command::Transfer {
            sndr,
            rcvr,
            amt,
            gas_limit,
            gas_price,
        } => {
            let sndr = sndr.as_ref().expect("valid address");
            let gas_limit = gas_limit.expect("gas limit not set");
            let gas_price = gas_price.expect("gas price not set");
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
            let addr = addr.as_ref().expect("valid address");
            let gas_limit = gas_limit.expect("gas limit not set");
            let gas_price = gas_price.expect("gas price not set");
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
            let addr = addr.as_ref().expect("valid address");
            let gas_limit = gas_limit.expect("gas limit not set");
            let gas_price = gas_price.expect("gas price not set");
            let max_fee = gas_limit * gas_price;
            println!("   > Unstake from {}", addr.preview());
            println!("   > Max fee = {} DUSK", Dusk::from(max_fee));
            prompt::ask_confirm()
        }
        Command::Withdraw {
            addr,
            refund_addr,
            gas_limit,
            gas_price,
        } => {
            let addr = addr.as_ref().expect("valid address");
            let gas_limit = gas_limit.expect("gas limit not set");
            let gas_price = gas_price.expect("gas price not set");
            let max_fee = gas_limit * gas_price;
            println!("   > Reward from {}", addr.preview());
            println!("   > Refund into {}", refund_addr.preview());
            println!("   > Max fee = {} DUSK", Dusk::from(max_fee));
            prompt::ask_confirm()
        }
        _ => true,
    }
}
