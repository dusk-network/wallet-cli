// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::fmt;
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
use crate::lib::dusk::{Dusk, Lux};
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

/// Possible results of running a command in interactive mode
pub enum RunResult {
    Empty,
    Balance(BalanceInfo),
    Address(String),
    TxHash(String),
    StakeInfo(dusk_wallet_core::StakeInfo),
    Export(String, String),
}

impl fmt::Display for RunResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use RunResult::*;
        match self {
            Balance(balance) => {
                write!(
                    f,
                    "> Total balance is: {} DUSK\n> Maximum spendable per TX is: {} DUSK",
                    Dusk::from(balance.value),
                    Dusk::from(balance.spendable)
                )
            }
            Address(addr) => {
                write!(f, "> {}", addr)
            }
            TxHash(txh) => {
                write!(f, "> Transaction sent: {}", txh)
            }
            StakeInfo(si) => {
                let stake_str = match si.amount {
                    Some((value, ..)) => format!(
                        "Current stake amount is: {} DUSK",
                        Dusk::from(value)
                    ),
                    None => "No active stake found for this key".to_string(),
                };
                write!(
                    f,
                    "> {}\n> Accumulated reward is: {} DUSK",
                    stake_str,
                    Dusk::from(si.reward)
                )
            }
            Export(key_pair, pub_key) => {
                write!(
                    f,
                    "> Key pair exported to {}\n> Pub key exported to {}",
                    key_pair, pub_key
                )
            }
            Empty => Ok(()),
        }
    }
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
                            PromptCommand::Unstake(key) => {
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
                    let cmd = match prompt::prepare_command(
                        pcmd,
                        balance.spendable.into(),
                    ) {
                        Ok(cmd) => cmd,
                        Err(err) => {
                            println!("{}", err);
                            None
                        }
                    };

                    if let Some(cmd) = cmd {
                        // run the command
                        prompt::hide_cursor()?;
                        let result = self.run(cmd);
                        prompt::show_cursor()?;

                        // output results
                        match result {
                            Ok(res) => {
                                println!("\r{}", res);
                                use RunResult::*;
                                if let TxHash(txh) = res {
                                    if let Some(base_url) =
                                        &self.config.explorer.tx_url
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

                    // wait for a second
                    thread::sleep(Duration::from_millis(1000));
                    println!("—");
                }
                None => return Ok(()),
            }
        }
    }

    /// Runs a command in interactive mode
    pub fn run(&self, cmd: CliCommand) -> Result<RunResult, Error> {
        use CliCommand::*;
        match cmd {
            Balance { key, .. } => {
                let balance = self.get_balance(key)?;
                Ok(RunResult::Balance(balance))
            }
            Address { key } => {
                let addr = self.get_address(key)?;
                Ok(RunResult::Address(addr))
            }
            Transfer {
                key,
                rcvr,
                amt,
                gas_limit,
                gas_price,
            } => {
                let txh =
                    self.transfer(key, &rcvr, amt, gas_limit, gas_price)?;
                Ok(RunResult::TxHash(txh))
            }
            Stake {
                key,
                stake_key,
                amt,
                gas_limit,
                gas_price,
            } => {
                let txh =
                    self.stake(key, stake_key, amt, gas_limit, gas_price)?;
                Ok(RunResult::TxHash(txh))
            }
            StakeInfo { key, .. } => {
                let si = self.stake_info(key)?;
                Ok(RunResult::StakeInfo(si))
            }
            Unstake {
                key,
                stake_key,
                gas_limit,
                gas_price,
            } => {
                let txh = self.unstake(key, stake_key, gas_limit, gas_price)?;
                Ok(RunResult::TxHash(txh))
            }
            Withdraw {
                key,
                stake_key,
                refund_addr,
                gas_limit,
                gas_price,
            } => {
                let txh = self.withdraw_reward(
                    key,
                    stake_key,
                    refund_addr,
                    gas_limit,
                    gas_price,
                )?;
                Ok(RunResult::TxHash(txh))
            }
            Export { key, plaintext } => {
                let (pk, sk) = self.export_keys(key, plaintext)?;
                Ok(RunResult::Export(pk, sk))
            }
            _ => Ok(RunResult::Empty),
        }
    }

    /// Requests balance for a given public spend key
    pub fn get_balance(&self, key: u64) -> Result<BalanceInfo, Error> {
        if let Some(wallet) = &self.wallet {
            wallet.get_balance(key).map_err(Error::from)
        } else {
            Err(Error::Offline)
        }
    }

    /// Obtains human-readable address for a given key index
    pub fn get_address(&self, key: u64) -> Result<String, Error> {
        let pk = if let Some(wallet) = &self.wallet {
            wallet.public_spend_key(key)?
        } else {
            let ssk = self.store.retrieve_ssk(key)?;
            ssk.public_spend_key()
        };
        let addr = pk.to_bytes();
        Ok(bs58::encode(addr).into_string())
    }

    /// Transfers DUSK through the network
    pub fn transfer(
        &self,
        key: u64,
        rcvr: &str,
        amt: Dusk,
        gas_limit: Option<u64>,
        gas_price: Option<Lux>,
    ) -> Result<String, Error> {
        if let Some(wallet) = &self.wallet {
            let mut rng = StdRng::from_entropy();
            let ref_id = BlsScalar::random(&mut rng);

            // check gas limits
            let gas_price = gas_price.unwrap_or(DEFAULT_GAS_PRICE);
            let gas_limit = gas_limit.unwrap_or(DEFAULT_GAS_LIMIT);
            if gas_limit < MIN_GAS_LIMIT {
                return Err(Error::NotEnoughGas);
            }

            // prepare public keys
            let mut addr_bytes = [0u8; SEED_SIZE];
            addr_bytes.copy_from_slice(&bs58::decode(rcvr).into_vec()?);
            let dest_addr = dusk_pki::PublicSpendKey::from_bytes(&addr_bytes)?;
            let my_addr = wallet.public_spend_key(key)?;

            // transfer
            let tx = wallet.transfer(
                &mut rng, key, &my_addr, &dest_addr, *amt, gas_limit,
                gas_price, ref_id,
            )?;

            // compute transaction id
            let txh = hex::encode(&tx.hash().to_bytes());
            Ok(txh)
        } else {
            Err(Error::Offline)
        }
    }

    // Start staking DUSK
    pub fn stake(
        &self,
        key: u64,
        stake_key: u64,
        amt: Dusk,
        gas_limit: Option<u64>,
        gas_price: Option<Lux>,
    ) -> Result<String, Error> {
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
            let mut rng = StdRng::from_entropy();

            // check gas limits
            let gas_price = gas_price.unwrap_or(DEFAULT_GAS_PRICE);
            let gas_limit = gas_limit.unwrap_or(DEFAULT_GAS_LIMIT);
            if gas_limit < MIN_GAS_LIMIT {
                return Err(Error::NotEnoughGas);
            }

            // prepare public key
            let my_addr = wallet.public_spend_key(key)?;

            // stake
            let tx = wallet.stake(
                &mut rng, key, stake_key, &my_addr, *amt, gas_limit, gas_price,
            )?;

            // compute transaction id
            let txh = hex::encode(&tx.hash().to_bytes());
            Ok(txh)
        } else {
            Err(Error::Offline)
        }
    }

    /// Check status of an existing stake
    pub fn stake_info(
        &self,
        key: u64,
    ) -> Result<dusk_wallet_core::StakeInfo, Error> {
        if let Some(wallet) = &self.wallet {
            wallet.get_stake(key).map_err(Error::from)
        } else {
            Err(Error::Offline)
        }
    }

    /// Stop staking
    pub fn unstake(
        &self,
        key: u64,
        stake_key: u64,
        gas_limit: Option<u64>,
        gas_price: Option<Lux>,
    ) -> Result<String, Error> {
        if let Some(wallet) = &self.wallet {
            let mut rng = StdRng::from_entropy();

            // check gas limits
            let gas_price = gas_price.unwrap_or(DEFAULT_GAS_PRICE);
            let gas_limit = gas_limit.unwrap_or(DEFAULT_GAS_LIMIT);
            if gas_limit < MIN_GAS_LIMIT {
                return Err(Error::NotEnoughGas);
            }

            // prepare public key
            let my_addr = wallet.public_spend_key(key)?;

            // unstake
            let tx = wallet.unstake(
                &mut rng, key, stake_key, &my_addr, gas_limit, gas_price,
            )?;

            // compute transaction id
            let txh = hex::encode(&tx.hash().to_bytes());
            Ok(txh)
        } else {
            Err(Error::Offline)
        }
    }

    /// Cash out the reward for an existing stake
    pub fn withdraw_reward(
        &self,
        key: u64,
        stake_key: u64,
        refund_addr: String,
        gas_limit: Option<u64>,
        gas_price: Option<Lux>,
    ) -> Result<String, Error> {
        if let Some(wallet) = &self.wallet {
            let mut rng = StdRng::from_entropy();

            // check gas limits
            let gas_price = gas_price.unwrap_or(DEFAULT_GAS_PRICE);
            let gas_limit = gas_limit.unwrap_or(DEFAULT_GAS_LIMIT);
            if gas_limit < MIN_GAS_LIMIT {
                return Err(Error::NotEnoughGas);
            }

            // refund address
            let mut addr_bytes = [0u8; SEED_SIZE];
            addr_bytes.copy_from_slice(&bs58::decode(refund_addr).into_vec()?);
            let refund_addr =
                dusk_pki::PublicSpendKey::from_bytes(&addr_bytes)?;

            // withdraw
            let tx = wallet.withdraw(
                &mut rng,
                key,
                stake_key,
                &refund_addr,
                gas_limit,
                gas_price,
            )?;

            // compute transaction id
            let txh = hex::encode(&tx.hash().to_bytes());
            Ok(txh)
        } else {
            Err(Error::Offline)
        }
    }

    /// Export keys for provisioner nodes
    pub fn export_keys(
        &self,
        key: u64,
        plaintext: bool,
    ) -> Result<(String, String), Error> {
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
        let key_pair = String::from(path.as_os_str().to_str().unwrap());

        // write pub key to disk
        let pkbytes = pk.to_bytes();
        path.set_extension("cpk");
        fs::write(&path, pkbytes)?;
        let pub_key = String::from(path.as_os_str().to_str().unwrap());

        Ok((key_pair, pub_key))
    }
}
