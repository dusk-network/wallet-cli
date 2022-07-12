// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use bip39::{Language, Mnemonic, Seed};
use blake3::Hash;
use dusk_bytes::Serializable;
use std::fmt::{Debug, Display};
use std::path::Path;

use dusk_bls12_381_sign::{PublicKey, SecretKey};
use dusk_jubjub::BlsScalar;
use dusk_pki::PublicSpendKey;
use dusk_wallet_core::{
    BalanceInfo, StakeInfo, Store, Transaction, Wallet as WalletCore,
};
use rand::prelude::StdRng;
use rand::SeedableRng;

use crate::clients::{Prover, State};
use crate::dusk::{Dusk, Lux};
use crate::rusk::{RuskClient, RuskEndpoint};
use crate::store::LocalStore;
use crate::{Error, StoreError};
use crate::{DEFAULT_GAS_LIMIT, DEFAULT_GAS_PRICE, MIN_GAS_LIMIT, SEED_SIZE};



/// The interface to the Dusk Network
/// 
/// The Wallet exposes all methods available to interact with the Dusk Network.
/// 
/// A new [`Wallet`] can be created from a bip39-compatible mnemonic phrase or an
/// existing wallet file.
/// 
/// The user can generate as many [`Address`] as needed without an active connection
/// to the network by calling [`Wallet::new_address`] repeatedly.
/// 
/// A wallet must connect to the network using a [`RuskEndpoint`] in order to be
/// able to perform common operations such as checking balance, transfernig funds,
/// or staking Dusk.
/// 


pub struct Wallet {
    store: LocalStore,
    wallet: Option<WalletCore<LocalStore, State, Prover>>,
    status: fn(status: &str),
    count: u64,
}

impl Wallet {

    /// Creates a new wallet instance deriving its seed from a valid BIP39 mnemonic
    pub fn new<S>(phrase: S) -> Result<Self, Error>
    where
        S: Into<String>,
    {
        // generate mnemonic
        let phrase: String = phrase.into();
        let mnemmonic = Mnemonic::from_phrase(&phrase, Language::English)
            .or_else(|_| Err(StoreError::InvalidMnemonicPhrase))?;

        // derive the seed
        let seed = Seed::new(&mnemmonic, "");
        let mut seed_bytes = [0u8; SEED_SIZE];
        seed_bytes.copy_from_slice(seed.as_bytes());

        // return new wallet instance
        Ok(Wallet {
            store: LocalStore::new(seed_bytes),
            wallet: None,
            status: |_| {},
            count: 0,
        })
    }

    /// Attempt to load an existing wallet from an encrypted wallet file
    pub fn from_file(filename: &Path, pwd: Hash) -> Result<Self, Error> {
        let store = LocalStore::from_file(filename, pwd)?;
        Ok(Wallet {
            store,
            wallet: None,
            status: |_| {},
            count: 0,
        })
    }

    /// Saves the wallet to an encrypted file
    pub fn save(&self, filename: &Path, pwd: Hash) -> Result<(), Error> {
        self.store.save(filename, pwd)?;
        Ok(())
    }

    /// Set a callback for status updates
    pub fn set_status_callback(&mut self, func: fn(&str)) {
        self.status = func
    }

    /// Connect the wallet to the network
    pub async fn connect<R>(&mut self, endpoint: R) -> Result<(), Error>
    where
        R: RuskEndpoint,
    {
        // attempt connection
        let rusk = RuskClient::connect(endpoint).await?;

        // create a prover client
        let prover = Prover::new(rusk.prover, rusk.state.clone(), rusk.network);

        // create a state client
        State::set_cache_dir(LocalStore::default_data_dir())?; // TODO: Should use wallet data dir?
        let state = State::new(rusk.state)?;

        // create wallet instance
        self.wallet = Some(WalletCore::new(self.store.clone(), state, prover));

        Ok(())
    }

    /// Obtain balance information for a given address
    pub async fn get_balance(
        &self,
        addr: &Address,
    ) -> Result<BalanceInfo, Error> {
        // make sure we own this address
        if !addr.is_owned() {
            return Err(Error::Unauthorized);
        }

        // get balance
        if let Some(wallet) = &self.wallet {
            let index =
                addr.index().expect("owned address should have an index");
            wallet.get_balance(index).map_err(Error::from)
        } else {
            Err(Error::Offline)
        }
    }

    /// Creates a new public address.
    /// The addresses generated are deterministic across sessions.
    pub fn new_address(&mut self) -> Address {
        let ssk = self
            .store
            .retrieve_ssk(self.count)
            .expect("wallet seed should be available");
        let addr = Address::new(self.count, ssk.public_spend_key());
        self.count += 1;
        addr
    }

    /// Transfers funds between addresses
    pub async fn transfer(
        &self,
        sender: &Address,
        rcvr: &Address,
        amt: Dusk,
        gas: Gas,
    ) -> Result<Transaction, Error> {
        if let Some(wallet) = &self.wallet {
            // make sure we own the sender address
            if !sender.is_owned() {
                return Err(Error::Unauthorized);
            }
            // make sure amount is positive
            if amt == 0 {
                return Err(Error::AmountIsZero);
            }
            // check gas limits
            if gas.limit < MIN_GAS_LIMIT {
                return Err(Error::NotEnoughGas);
            }

            let mut rng = StdRng::from_entropy();
            let ref_id = BlsScalar::random(&mut rng);
            let sender_index =
                sender.index().expect("owned address should have an index");

            // transfer
            let tx = wallet.transfer(
                &mut rng,
                sender_index,
                sender.psk(),
                rcvr.psk(),
                *amt,
                gas.limit(),
                gas.price(),
                ref_id,
            )?;
            Ok(tx)
        } else {
            Err(Error::Offline)
        }
    }

    pub async fn stake(
        &self,
        addr: &Address,
        amt: Dusk,
        gas: Gas,
    ) -> Result<Transaction, Error> {
        if let Some(wallet) = &self.wallet {
            // make sure we own the staking address
            if !addr.is_owned() {
                return Err(Error::Unauthorized);
            }
            // make sure amount is positive
            if amt == 0 {
                return Err(Error::AmountIsZero);
            }
            // check gas limits
            if gas.limit < MIN_GAS_LIMIT {
                return Err(Error::NotEnoughGas);
            }

            let mut rng = StdRng::from_entropy();
            let sender_index =
                addr.index().expect("owned address should have an index");

            // stake
            let tx = wallet.stake(
                &mut rng,
                sender_index,
                sender_index,
                addr.psk(),
                *amt,
                gas.limit(),
                gas.price(),
            )?;
            Ok(tx)
        } else {
            Err(Error::Offline)
        }
    }

    pub async fn stake_info(&self, addr: &Address) -> Result<StakeInfo, Error> {
        if let Some(wallet) = &self.wallet {
            // make sure we own the staking address
            if !addr.is_owned() {
                return Err(Error::Unauthorized);
            }
            let index =
                addr.index().expect("owned address should have an index");
            wallet.get_stake(index).map_err(Error::from)
        } else {
            Err(Error::Offline)
        }
    }

    pub async fn unstake(
        &self,
        addr: &Address,
        gas: Gas,
    ) -> Result<Transaction, Error> {
        if let Some(wallet) = &self.wallet {
            // make sure we own the staking address
            if !addr.is_owned() {
                return Err(Error::Unauthorized);
            }

            let mut rng = StdRng::from_entropy();
            let index =
                addr.index().expect("owned address should have an index");

            let tx = wallet.unstake(
                &mut rng,
                index,
                index,
                addr.psk(),
                gas.limit(),
                gas.price(),
            )?;
            Ok(tx)
        } else {
            Err(Error::Offline)
        }
    }

    pub async fn withdraw_reward(
        &self,
        addr: &Address,
        refund_addr: &Address,
        gas: Gas,
    ) -> Result<Transaction, Error> {
        if let Some(wallet) = &self.wallet {
            // make sure we own the staking address
            if !addr.is_owned() {
                return Err(Error::Unauthorized);
            }

            let mut rng = StdRng::from_entropy();
            let index =
                addr.index().expect("owned address should have an index");

            let tx = wallet.withdraw(
                &mut rng,
                index,
                index,
                refund_addr.psk(),
                gas.limit(),
                gas.price(),
            )?;
            Ok(tx)
        } else {
            Err(Error::Offline)
        }
    }

    /// Export keys for provisioner nodes
    pub fn export_keys(
        &self,
        addr: Address,
    ) -> Result<(SecretKey, PublicKey), Error> {
        // make sure we own the staking address
        if !addr.is_owned() {
            return Err(Error::Unauthorized);
        }

        let index = addr.index().expect("owned address should have an index");

        // retrieve keys
        let sk = self.store.retrieve_sk(index)?;
        let pk: PublicKey = From::from(&sk);

        Ok((sk, pk))
    }
}

/// A public address within the Dusk Network
pub struct Address {
    index: Option<u64>,
    psk: PublicSpendKey,
}

impl Address {

    pub(crate) fn new(index: u64, psk: PublicSpendKey) -> Self {
        Self {
            index: Some(index),
            psk,
        }
    }

    /// Returns true if the current user owns this address
    pub fn is_owned(&self) -> bool {
        self.index.is_some()
    }

    pub(crate) fn psk(&self) -> &PublicSpendKey {
        &self.psk
    }

    pub(crate) fn index(&self) -> &Option<u64> {
        &self.index
    }

}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bs58::encode(self.psk.to_bytes()).into_string())
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bs58::encode(self.psk.to_bytes()).into_string())
    }
}


#[derive(Debug)]
/// Gas price and limit for any transaction
pub struct Gas {
    price: Lux,
    limit: u64,
}

impl Gas {

    /// Default gas price and limit
    pub fn new() -> Self {
        Gas {
            price: DEFAULT_GAS_PRICE,
            limit: DEFAULT_GAS_LIMIT,
        }
    }

    /// Set a custom gas price in Lux
    pub fn set_price(&mut self, price: Lux) {
        self.price = price;
    }

    /// Set a custom gas limit amount
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    /// Get gas price
    pub fn price(&self) -> Lux {
        self.price
    }

    /// Get gas limit
    pub fn limit(&self) -> u64 {
        self.limit
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use tempfile::tempdir;

    const TEST_ADDR: &str = "2w7fRQW23Jn9Bgm1GQW9eC2bD9U883dAwqP7HAr2F8g1syzPQaPYrxSyyVZ81yDS5C1rv9L8KjdPBsvYawSx3QCW";

    #[test]
    fn create_from_mnemonic() -> Result<(), Box<dyn std::error::Error>> {

        let mut wallet = Wallet::new("uphold stove tennis fire menu three quick apple close guilt poem garlic volcano giggle comic")?;
        let addr = wallet.new_address();
        assert!(format!("{}", addr).eq(TEST_ADDR));

        let mut wallet = Wallet::new("demise monitor elegant cradle squeeze cheap parrot venture stereo humor scout denial action receive flat")?;
        let addr = wallet.new_address();
        assert!(format!("{}", addr).ne(TEST_ADDR));

        assert!(Wallet::new("good luck with life").is_err());
        Ok(())

    }

    #[test]
    fn save_and_load() -> Result<(), Box<dyn std::error::Error>> {

        // create and save
        let wallet = Wallet::new("uphold stove tennis fire menu three quick apple close guilt poem garlic volcano giggle comic")?;
        let dir = tempdir()?;
        let path = dir.path().join("my_wallet.dat");

        let pwd = blake3::hash("mypassword".as_bytes());
        wallet.save(&path, pwd)?;

        // load from file and check
        let mut loaded_wallet = Wallet::from_file(&path, pwd)?;
        let addr = loaded_wallet.new_address();
        assert!(format!("{}", addr).eq(TEST_ADDR));
 
        Ok(())

    }

}

