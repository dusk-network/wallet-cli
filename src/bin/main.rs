// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use anyhow::Result;
use clap::Parser;
use tracing::Level;

mod args;
mod command;
mod interactive;
mod menu;
mod node;
mod prompt;
mod prover;
mod settings;
mod storage;

type Wallet =
    dusk_wallet::wallet::Wallet<storage::Storage, node::Node, prover::Prover>;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    if let Err(err) = exec().await {
        // display the error message (if any)
        match err.downcast_ref::<requestty::ErrorKind>() {
            Some(requestty::ErrorKind::Interrupted) => {
                // TODO: Handle this error properly
                // See also https://github.com/dusk-network/wallet-cli/issues/104
            }
            _ => eprintln!("{err}"),
        };
        // give cursor back to the user
        prompt::show_cursor()?;
    }

    Ok(())
}

async fn exec() -> anyhow::Result<()> {
    // parse user args
    let args = args::WalletArgs::parse();

    // get the subcommand, if any
    let cmd = args.command.clone();

    // set symbols to ASCII for Windows terminal compatibility
    #[cfg(windows)]
    requestty::symbols::set(requestty::symbols::ASCII);

    // Get the initial settings from the args
    let wallet = args.wallet.clone();
    let settings_builder = settings::Settings::args(args);

    // Finalize the settings
    let settings = settings_builder.build();

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
        settings::LogFormat::Json => {
            let subscriber = subscriber.json().flatten_event(true).finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
        settings::LogFormat::Plain => {
            let subscriber = subscriber.with_ansi(false).finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
        settings::LogFormat::Coloured => {
            let subscriber = subscriber.finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
    };

    match cmd {
        Some(ref cmd) if cmd == &command::Command::Settings => {
            println!("{}", &settings);
            return Ok(());
        }
        _ => {}
    };

    let storage = storage::Storage::new(&settings);
    let node = node::Node::new(&settings);
    let prover = prover::Prover::new(&settings);
    let mut wallet = Wallet::new(wallet, storage, node, prover)?;

    let key = wallet.public_spend_keys().await?[0].clone();
    wallet.node.mint(key, 1000).await?;
    wallet.sync().await?;

    // run command
    match cmd {
        Some(cmd) => match cmd.run(&mut wallet, &settings).await? {
            command::RunResult::Balance { value, .. } => {
                println!("{}", value);
            }
            command::RunResult::Addresses(addrs) => {
                for a in addrs {
                    println!("{}", a);
                }
            }
            command::RunResult::Settings => {}
        },
        None => {
            interactive::run_loop(&mut wallet, &settings).await?;
        }
    }

    Ok(())
}
