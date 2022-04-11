// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::{fs, thread, time::Duration};

use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Serialize;

use dusk_bytes::Serializable;
use dusk_jubjub::BlsScalar;
use dusk_wallet_core::{BalanceInfo, Store, Wallet};

use crate::lib::clients::{Prover, State};
use crate::lib::config::Config;
use crate::lib::crypto::encrypt;
use crate::lib::dusk::Dusk;
use crate::lib::store::LocalStore;
use crate::lib::{
    prompt, DEFAULT_GAS_LIMIT, DEFAULT_GAS_PRICE, MIN_GAS_LIMIT, SEED_SIZE,
};
use crate::{CliCommand, Error};

mod base64 {
    use serde::{Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64::encode(v);
        String::serialize(&base64, s)
    }
}

/// Bls key pair helper structure
#[derive(Serialize)]
struct BlsKeyPair {
    #[serde(with = "base64")]
    secret_key_bls: [u8; 32],
    #[serde(with = "base64")]
    public_key_bls: [u8; 96],
}

/// Interface to wallet_core lib
pub(crate) struct CliWallet {
    config: Config,
    store: LocalStore,
    wallet: Option<Wallet<LocalStore, State, Prover>>,
}

impl CliWallet {
    /// Creates a new CliWallet instance
    pub fn new(
        cfg: Config,
        store: LocalStore,
        state: State,
        prover: Prover,
    ) -> Self {
        CliWallet {
            config: cfg,
            store: store.clone(),
            wallet: Some(Wallet::new(store, state, prover)),
        }
    }

    /// Creates a new offline CliWallet instance
    pub fn offline(config: Config, store: LocalStore) -> Self {
        CliWallet {
            config,
            store,
            wallet: None,
        }
    }

    /// Runs the CliWallet in interactive mode
    pub fn interactive(&self) -> Result<(), Error> {
        let offline = self.wallet.is_none();
        loop {
            use prompt::PromptCommand;
            match prompt::choose_command(offline) {
                Some(pcmd) => {
                    // load key balance first to provide interactive feedback
                    prompt::hide_cursor()?;
                    let balance = if let Some(wallet) = &self.wallet {
                        match pcmd {
                            PromptCommand::Transfer(key) => {
                                wallet.get_balance(key)?
                            }
                            PromptCommand::Stake(key) => {
                                wallet.get_balance(key)?
                            }
                            PromptCommand::Withdraw(key) => {
                                wallet.get_balance(key)?
                            }
                            // these commands don't require balance
                            _ => BalanceInfo {
                                value: 0,
                                spendable: 0,
                            },
                        }
                    } else {
                        BalanceInfo {
                            value: 0,
                            spendable: 0,
                        }
                    };
                    prompt::show_cursor()?;

                    // prepare command
                    if let Some(cmd) =
                        prompt::prepare_command(pcmd, balance.spendable.into())?
                    {
                        // run command
                        if let Some(txh) = self.run(cmd)? {
                            println!("\r> Transaction sent: {}", txh);
                            if let Some(base_url) = &self.config.explorer.tx_url
                            {
                                let url = format!("{}{}", base_url, txh);
                                println!("> URL: {}", url);
                                prompt::launch_explorer(url);
                            };
                        }
                    }

                    // wait for a second
                    thread::sleep(Duration::from_millis(1000));
                    println!("—")
                }
                None => return Ok(()),
            }
        }
    }

    /// Runs a command through wallet core lib
    /// On transactions, the transaction ID is returned
    pub fn run(&self, cmd: CliCommand) -> Result<Option<String>, Error> {
        // perform whatever action user requested
        use CliCommand::*;
        match cmd {
            // Check your current balance
            Balance { key } => {
                if let Some(wallet) = &self.wallet {
                    prompt::hide_cursor()?;
                    let balance = wallet.get_balance(key)?;
                    println!(
                        "\r> Total balance for key {} is: {} DUSK",
                        key,
                        Dusk::from(balance.value)
                    );
                    println!(
                        "\r> Maximum spendable per TX is: {} DUSK",
                        Dusk::from(balance.spendable)
                    );
                    prompt::show_cursor()?;
                    Ok(None)
                } else {
                    Err(Error::Offline)
                }
            }

            // Retrieve public spend key
            Address { key } => {
                prompt::hide_cursor()?;
                let pk = if let Some(wallet) = &self.wallet {
                    wallet.public_spend_key(key)?
                } else {
                    let ssk = self.store.retrieve_ssk(key)?;
                    ssk.public_spend_key()
                };
                prompt::show_cursor()?;
                let addr = pk.to_bytes();
                let addr = bs58::encode(addr).into_string();
                println!("\r> {}", addr);
                Ok(None)
            }

            // Send DUSK through the network
            Transfer {
                key,
                rcvr,
                amt,
                gas_limit,
                gas_price,
            } => {
                if let Some(wallet) = &self.wallet {
                    // prepare public keys
                    let mut addr_bytes = [0u8; SEED_SIZE];
                    addr_bytes.copy_from_slice(&bs58::decode(rcvr).into_vec()?);
                    let dest_addr =
                        dusk_pki::PublicSpendKey::from_bytes(&addr_bytes)?;
                    let my_addr = wallet.public_spend_key(key)?;

                    let mut rng = StdRng::from_entropy();
                    let ref_id = BlsScalar::random(&mut rng);

                    let gas_price = gas_price.unwrap_or(DEFAULT_GAS_PRICE);
                    let gas_limit = gas_limit.unwrap_or(DEFAULT_GAS_LIMIT);
                    if gas_limit < MIN_GAS_LIMIT {
                        return Err(Error::NotEnoughGas);
                    }

                    // transfer
                    prompt::hide_cursor()?;
                    let tx = wallet.transfer(
                        &mut rng, key, &my_addr, &dest_addr, *amt, gas_limit,
                        gas_price, ref_id,
                    )?;
                    prompt::show_cursor()?;

                    // compute transaction id
                    let txh = hex::encode(&tx.hash().to_bytes());
                    Ok(Some(txh))
                } else {
                    Err(Error::Offline)
                }
            }

            // Start staking DUSK
            Stake {
                key,
                stake_key,
                amt,
                gas_limit,
                gas_price,
            } => {
                // prevent users not running a local rusk instance from staking
                const MATCHES: [&str; 2] = ["localhost", "127.0.0.1"];
                let mut local_rusk = false;
                for m in MATCHES.into_iter() {
                    if self.config.rusk.rusk_addr.contains(m) {
                        local_rusk = true;
                        break;
                    }
                }
                if !local_rusk {
                    return Err(Error::StakingNotAllowed);
                }

                if let Some(wallet) = &self.wallet {
                    let my_addr = wallet.public_spend_key(key)?;
                    let mut rng = StdRng::from_entropy();

                    let gas_limit = gas_limit.unwrap_or(DEFAULT_GAS_LIMIT);
                    if gas_limit < MIN_GAS_LIMIT {
                        return Err(Error::NotEnoughGas);
                    }

                    prompt::hide_cursor()?;
                    let tx = wallet.stake(
                        &mut rng,
                        key,
                        stake_key,
                        &my_addr,
                        *amt,
                        gas_limit,
                        gas_price.unwrap_or(DEFAULT_GAS_PRICE),
                    )?;
                    prompt::show_cursor()?;

                    // compute transaction id
                    let txh = hex::encode(&tx.hash().to_bytes());
                    Ok(Some(txh))
                } else {
                    Err(Error::Offline)
                }
            }

            // Check your current stake
            StakeInfo { key } => {
                if let Some(wallet) = &self.wallet {
                    prompt::hide_cursor()?;
                    let stake = wallet.get_stake(key)?;
                    println!("\r> Staking {} DUSK", Dusk::from(stake.value));
                    println!(
                        "> Stake created at block {} and valid since block {}",
                        &stake.created_at, &stake.eligibility
                    );
                    prompt::show_cursor()?;
                    Ok(None)
                } else {
                    Err(Error::Offline)
                }
            }

            // Withdraw a key's stake
            WithdrawStake {
                key,
                stake_key,
                gas_limit,
                gas_price,
            } => {
                if let Some(wallet) = &self.wallet {
                    let my_addr = wallet.public_spend_key(key)?;
                    let mut rng = StdRng::from_entropy();

                    let gas_limit = gas_limit.unwrap_or(DEFAULT_GAS_LIMIT);
                    if gas_limit < MIN_GAS_LIMIT {
                        return Err(Error::NotEnoughGas);
                    }

                    prompt::hide_cursor()?;
                    let tx = wallet.withdraw_stake(
                        &mut rng,
                        key,
                        stake_key,
                        &my_addr,
                        gas_limit,
                        gas_price.unwrap_or(DEFAULT_GAS_PRICE),
                    )?;
                    prompt::show_cursor()?;

                    // compute tx id
                    let txh = hex::encode(&tx.hash().to_bytes());
                    Ok(Some(txh))
                } else {
                    Err(Error::Offline)
                }
            }

            Export { key, plaintext } => {
                // retrieve keys
                let sk = self.store.retrieve_sk(key)?;
                let pk = if let Some(wallet) = &self.wallet {
                    wallet.public_key(key)?
                } else {
                    From::from(&sk)
                };

                // create node-compatible json structure
                let bls = BlsKeyPair {
                    secret_key_bls: sk.to_bytes(),
                    public_key_bls: pk.to_bytes(),
                };
                let json = serde_json::to_string(&bls)?;

                // encrypt data
                let mut bytes = json.as_bytes().to_vec();
                if !plaintext {
                    let pwd = prompt::request_auth("Encryption password");
                    bytes = encrypt(&bytes, pwd)?;
                }

                // add wallet name to file
                let filename = match self.store.name() {
                    Some(name) => format!("{}-{}", name, key),
                    None => key.to_string(),
                };

                // output directory
                let mut path = self
                    .store
                    .dir()
                    .unwrap_or_else(LocalStore::default_data_dir);
                path.push(&filename);
                path.set_extension("key");

                // write key pair to disk
                fs::write(&path, bytes)?;

                println!(
                    "> Key pair exported to {}",
                    path.as_os_str().to_str().unwrap()
                );

                // write pub key to disk
                let pkbytes = pk.to_bytes();
                path.set_extension("cpk");
                fs::write(&path, pkbytes)?;

                println!(
                    "> Pub key exported to {}",
                    path.as_os_str().to_str().unwrap()
                );

                Ok(None)
            }

            // Do nothing
            _ => Ok(None),
        }
    }
}
