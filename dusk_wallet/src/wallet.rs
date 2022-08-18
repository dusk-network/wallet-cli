// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use bip39::{Language, Mnemonic, Seed};
use blake3::Hash;
use dusk_bytes::Serializable;
use serde::Serialize;
use std::fmt;
use std::fmt::{Debug, Display};
use std::fs;
use std::hash::Hasher;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use dusk_bls12_381_sign::{PublicKey, SecretKey};
use dusk_jubjub::BlsScalar;
use dusk_pki::PublicSpendKey;
use dusk_wallet_core::{
    BalanceInfo, StakeInfo, Store, Transaction, Wallet as WalletCore,
};
use rand::prelude::StdRng;
use rand::SeedableRng;

use crate::clients::{Prover, State};
use crate::crypto::{decrypt, encrypt};
use crate::dusk::{Dusk, Lux};
use crate::rusk::{RuskClient, RuskEndpoint};
use crate::store::LocalStore;
use crate::Error;
use crate::{DEFAULT_GAS_LIMIT, DEFAULT_GAS_PRICE, MIN_GAS_LIMIT, SEED_SIZE};

/// Default data directory name
pub(crate) const DATA_DIR: &str = ".dusk";
/// Binary prefix for Dusk wallet files
const MAGIC: &[u8] = &[21, 12, 29];
/// Specifies the encoding used to save files
const VERSION: &[u8] = &[2, 0];

/// The interface to the Dusk Network
///
/// The Wallet exposes all methods available to interact with the Dusk Network.
///
/// A new [`Wallet`] can be created from a bip39-compatible mnemonic phrase or
/// an existing wallet file.
///
/// The user can generate as many [`Address`] as needed without an active
/// connection to the network by calling [`Wallet::new_address`] repeatedly.
///
/// A wallet must connect to the network using a [`RuskEndpoint`] in order to be
/// able to perform common operations such as checking balance, transfernig
/// funds, or staking Dusk.

pub struct Wallet<F: SecureWalletFile> {
    wallet: Option<WalletCore<LocalStore, State, Prover>>,
    addrs: Addresses,
    store: LocalStore,
    file: Option<F>,
    status: fn(status: &str),
}

/// Provides access to a secure wallet file
pub trait SecureWalletFile {
    fn path(&self) -> &WalletPath;
    fn pwd(&self) -> Hash;
}

impl<F: SecureWalletFile> Wallet<F> {
    /// Creates a new wallet instance deriving its seed from a valid BIP39
    /// mnemonic
    pub fn new<P>(phrase: P) -> Result<Self, Error>
    where
        P: Into<String>,
    {
        // generate mnemonic
        let phrase: String = phrase.into();
        let try_mnem = Mnemonic::from_phrase(&phrase, Language::English);

        if let Ok(mnemonic) = try_mnem {
            // derive the seed
            let seed = Seed::new(&mnemonic, "");
            let mut seed_bytes = [0u8; SEED_SIZE];
            seed_bytes.copy_from_slice(seed.as_bytes());

            // return new wallet instance
            Ok(Wallet {
                wallet: None,
                addrs: Addresses::default(),
                store: LocalStore::new(seed_bytes),
                file: None,
                status: |_| {},
            })
        } else {
            Err(Error::InvalidMnemonicPhrase)
        }
    }

    /// Loads wallet given a session
    pub fn from_file(file: F) -> Result<Self, Error> {
        let path = file.path();
        let pwd = file.pwd();

        // make sure file exists
        let pb = path.inner().clone();
        if !pb.is_file() {
            return Err(Error::WalletFileNotExists);
        }

        // attempt to load and decode wallet
        let mut bytes = fs::read(&pb)?;

        // check for magic number
        for i in 0..3 {
            if bytes[i] != MAGIC[i] {
                return Self::from_legacy_file(file);
            }
        }
        bytes.drain(..3);

        // check for version information
        let [major, minor] = [bytes[0], bytes[1]];
        bytes.drain(..2);

        // prepare our receiver structs
        let mut seed = [0u8; SEED_SIZE];
        let mut addrs = Addresses::default();

        // decrypt and interpret file contents
        match (major, minor) {
            (1, 0) => {
                bytes = decrypt(&bytes, pwd)?;
                if bytes.len() != SEED_SIZE {
                    return Err(Error::WalletFileCorrupted);
                }
                seed.copy_from_slice(&bytes);
            }
            (2, 0) => {
                let content = decrypt(&bytes, pwd)?;
                // extract seed
                seed.copy_from_slice(&content[0..SEED_SIZE]);
                // extract addrs
                let mut addrs_bytes = [0u8; 8];
                addrs_bytes.copy_from_slice(&content[SEED_SIZE..]);
                addrs = Addresses::from_bytes(&addrs_bytes)?
            }
            _ => {
                return Err(Error::UnknownFileVersion(major, minor));
            }
        };

        // create and return
        Ok(Self {
            wallet: None,
            addrs,
            store: LocalStore::new(seed),
            file: Some(file),
            status: |_| {},
        })
    }

    /// Attempts to load a legacy wallet file (no version number)
    fn from_legacy_file(file: F) -> Result<Self, Error> {
        let path = file.path();
        let pwd = file.pwd();

        // attempt to load and decode wallet
        let mut bytes = fs::read(path.inner())?;

        // check for old version information and strip it if present
        if bytes[1] == 0 && bytes[2] == 0 {
            bytes.drain(..3);
        }

        bytes = decrypt(&bytes, pwd)?;
        if bytes.len() != SEED_SIZE {
            return Err(Error::WalletFileCorrupted);
        }

        // get our seed
        let mut seed = [0u8; SEED_SIZE];
        seed.copy_from_slice(&bytes);

        // return the store
        Ok(Self {
            wallet: None,
            addrs: Addresses::default(),
            store: LocalStore::new(seed),
            file: Some(file),
            status: |_| {},
        })
    }

    /// Saves wallet to file from which it was loaded
    pub fn save(&self) -> Result<(), Error> {
        match &self.file {
            Some(f) => {
                // create file content
                let seed = self.store.get_seed()?;
                let mut content = seed.to_vec();
                content.append(&mut self.addrs.to_bytes().to_vec());

                // encrypt everything
                content = encrypt(&content, f.pwd())?;

                // prepend magic number and encoding version information
                let mut prefix = [0u8; MAGIC.len() + VERSION.len()];
                prefix[..MAGIC.len()].copy_from_slice(MAGIC);
                prefix[MAGIC.len()..].copy_from_slice(VERSION);
                content.splice(0..0, prefix.iter().cloned());

                // write to file
                fs::write(Path::new(&f.path().0), content)?;
                Ok(())
            }
            None => Err(Error::WalletFileMissing),
        }
    }

    /// Saves wallet to the provided file, changing the previous file path for
    /// the wallet if any. Note that any subsequent calls to [`save`] will
    /// use this new file.
    pub fn save_to(&mut self, file: F) -> Result<(), Error> {
        // set our new file and save
        self.file = Some(file);
        self.save()
    }

    /// Connect the wallet to the network providing a callback for status
    /// updates
    pub async fn connect_with_status<R>(
        &mut self,
        endpoint: R,
        status: fn(&str),
    ) -> Result<(), Error>
    where
        R: RuskEndpoint,
    {
        // attempt connection
        let rusk = RuskClient::connect(endpoint).await?;

        // create a prover client
        let mut prover =
            Prover::new(rusk.prover, rusk.state.clone(), rusk.network);
        prover.set_status_callback(status);

        // create a state client
        let mut state = State::new(rusk.state)?;
        state.set_status_callback(status);

        // create wallet instance
        self.wallet = Some(WalletCore::new(self.store.clone(), state, prover));

        // set our own status callback
        self.status = status;

        Ok(())
    }

    /// Checks if the wallet has an active connection to the network
    pub fn is_online(&self) -> bool {
        self.wallet.is_some()
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
            let index = addr.index()?;
            Ok(wallet.get_balance(index)?)
        } else {
            Err(Error::Offline)
        }
    }

    /// Creates a new public address.
    /// The addresses generated are deterministic across sessions.
    pub fn new_address(&mut self) -> Address {
        let addr = self.get_address(self.addrs.count);
        self.addrs.count += 1;
        addr
    }

    /// Default public address for this wallet
    pub fn default_address(&self) -> Address {
        let ssk = self
            .store
            .retrieve_ssk(0)
            .expect("wallet seed should be available");
        Address::new(0, ssk.public_spend_key())
    }

    fn get_address(&self, index: u64) -> Address {
        let ssk = self
            .store
            .retrieve_ssk(index)
            .expect("wallet seed should be available");
        Address::new(index, ssk.public_spend_key())
    }

    /// Addresses that have been generated by the user
    pub fn addresses(&self) -> Vec<Address> {
        (0..self.address_count())
            .map(|i| self.get_address(i))
            .collect()
    }

    /// Generated address count for this wallet
    pub fn address_count(&self) -> u64 {
        self.addrs.count
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

    /// Stakes Dusk
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
            let sender_index = addr.index()?;

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

    /// Obtains stake information for a given address
    pub async fn stake_info(&self, addr: &Address) -> Result<StakeInfo, Error> {
        if let Some(wallet) = &self.wallet {
            // make sure we own the staking address
            if !addr.is_owned() {
                return Err(Error::Unauthorized);
            }
            let index = addr.index()?;
            wallet.get_stake(index).map_err(Error::from)
        } else {
            Err(Error::Offline)
        }
    }

    /// Unstakes Dusk
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
            let index = addr.index()?;

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

    /// Withdraw accumulated staking reward for a given address
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
            let index = addr.index()?;

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

    /// Returns bls key pair for provisioner nodes
    pub fn provisioner_keys(
        &self,
        addr: &Address,
    ) -> Result<(PublicKey, SecretKey), Error> {
        // make sure we own the staking address
        if !addr.is_owned() {
            return Err(Error::Unauthorized);
        }

        let index = addr.index()?;

        // retrieve keys
        let sk = self.store.retrieve_sk(index)?;
        let pk: PublicKey = From::from(&sk);

        Ok((pk, sk))
    }

    /// Export bls key pair for provisioners in node-compatible format
    pub fn export_keys(
        &self,
        addr: &Address,
        dir: &Path,
        pwd: Hash,
    ) -> Result<(PathBuf, PathBuf), Error> {
        // we're expecting a directory here
        if !dir.is_dir() {
            return Err(Error::NotDirectory);
        }

        // get our keys for this address
        let keys = self.provisioner_keys(addr)?;

        // set up the path
        let mut path = PathBuf::from(dir);
        path.push(addr.preview());

        // export public key to disk
        let bytes = keys.0.to_bytes();
        fs::write(&path.with_extension("key"), bytes)?;

        // create node-compatible json structure
        let bls = BlsKeyPair {
            public_key_bls: keys.0.to_bytes(),
            secret_key_bls: keys.1.to_bytes(),
        };
        let json = serde_json::to_string(&bls)?;

        // encrypt data
        let mut bytes = json.as_bytes().to_vec();
        bytes = crate::crypto::encrypt(&bytes, pwd)?;

        // export key pair to disk
        fs::write(&path.with_extension("cpk"), bytes)?;

        Ok((path.with_extension("key"), path.with_extension("cpk")))
    }

    /// Obtain the owned `Address` for a given address
    pub fn claim_as_address(&self, addr: Address) -> Result<Address, Error> {
        self.addresses()
            .into_iter()
            .find(|a| a.psk == addr.psk)
            .ok_or(Error::AddressNotOwned)
    }
}

/// A public address within the Dusk Network
#[derive(Clone, Eq)]
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

    pub(crate) fn index(&self) -> Result<u64, Error> {
        self.index.ok_or(Error::AddressNotOwned)
    }

    /// A trimmed version of the address to display as preview
    pub fn preview(&self) -> String {
        let addr = bs58::encode(self.psk.to_bytes()).into_string();
        (&addr[..10]).to_string()
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let dec = bs58::decode(s).into_vec()?;
        if dec.len() != SEED_SIZE {
            return Err(Error::BadAddress);
        }
        let mut addr_bytes = [0u8; SEED_SIZE];
        addr_bytes.copy_from_slice(&dec);
        let addr = Address {
            index: None,
            psk: dusk_pki::PublicSpendKey::from_bytes(&addr_bytes)?,
        };
        Ok(addr)
    }
}

impl TryFrom<String> for Address {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let dec = bs58::decode(s).into_vec()?;
        if dec.len() != SEED_SIZE {
            return Err(Error::BadAddress);
        }
        let mut addr_bytes = [0u8; SEED_SIZE];
        addr_bytes.copy_from_slice(&dec);
        let addr = Address {
            index: None,
            psk: dusk_pki::PublicSpendKey::from_bytes(&addr_bytes)?,
        };
        Ok(addr)
    }
}

impl TryFrom<&[u8; 64]> for Address {
    type Error = Error;

    fn try_from(bytes: &[u8; 64]) -> Result<Self, Self::Error> {
        let addr = Address {
            index: None,
            psk: dusk_pki::PublicSpendKey::from_bytes(bytes)?,
        };
        Ok(addr)
    }
}

impl PartialEq for Address {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index && self.psk == other.psk
    }
}

impl std::hash::Hash for Address {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.index.hash(state);
        self.psk.to_bytes().hash(state);
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.psk.to_bytes()).into_string())
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.psk.to_bytes()).into_string())
    }
}

/// Addresses holds address-related metadata that needs to be
/// persisted in the wallet file.
struct Addresses {
    count: u64,
}

impl Default for Addresses {
    fn default() -> Self {
        Self { count: 1 }
    }
}

impl Serializable<8> for Addresses {
    const SIZE: usize = 8;

    type Error = Error;

    fn from_bytes(buf: &[u8; 8]) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self {
            count: u64::from_le_bytes(*buf),
        })
    }

    fn to_bytes(&self) -> [u8; 8] {
        self.count.to_le_bytes()
    }
}

/// Wrapper around `PathBuf` for wallet paths
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct WalletPath(PathBuf);

impl WalletPath {
    /// Create a new wallet path from a directory and a name
    pub fn new(dir: &Path, name: String) -> Self {
        let mut pb = PathBuf::from(dir);
        pb.push(name);
        pb.set_extension("dat");
        Self(pb)
    }

    /// Returns the filename of this path
    pub fn name(&self) -> Option<String> {
        // extract the name
        let name = self.0.file_stem()?.to_str()?;
        Some(String::from(name))
    }

    /// Returns current directory for this path
    pub fn dir(&self) -> Option<PathBuf> {
        self.0.parent().map(PathBuf::from)
    }

    /// Returns a reference to the `PathBuf` holding the path
    pub fn inner(&self) -> &PathBuf {
        &self.0
    }

    /// Sets the directory for the state cache
    pub fn set_cache_dir(path: &Path) -> Result<(), Error> {
        Ok(State::set_cache_dir(path.to_path_buf())?)
    }

    /// Wallet name defaults to user's username
    pub fn default_name() -> String {
        // get default user as default wallet name (remove whitespace)
        let mut user: String = whoami::username();
        user.retain(|c| !c.is_whitespace());
        user
    }

    /// Wallet default directory defaults to user's home directory
    pub fn default_dir() -> PathBuf {
        let home = dirs::home_dir().expect("OS not supported");
        Path::new(home.as_os_str()).join(DATA_DIR)
    }

    /// Checks if a wallet with this name already exists
    pub fn exists(dir: &Path, name: &str) -> bool {
        let mut pb = dir.to_path_buf();
        pb.push(name);
        pb.set_extension("dat");
        pb.is_file()
    }

    /// Get full paths of all wallet files found in `dir`
    pub fn wallets_in(dir: &Path) -> Result<Vec<WalletPath>, Error> {
        let dir = fs::read_dir(dir)?;
        let wallets = dir
            .filter_map(|el| el.ok().map(|d| d.path()))
            .filter(|path| path.is_file())
            .filter(|path| match path.extension() {
                Some(ext) => ext == "dat",
                None => false,
            })
            .map(WalletPath)
            .collect();

        Ok(wallets)
    }
}

impl Default for WalletPath {
    fn default() -> Self {
        let mut pb = Self::default_dir();
        pb.push(Self::default_name());
        pb.set_extension("dat");
        WalletPath(pb)
    }
}

impl FromStr for WalletPath {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let p = Path::new(s);
        Ok(Self(p.to_owned()))
    }
}

impl From<PathBuf> for WalletPath {
    fn from(p: PathBuf) -> Self {
        Self(p)
    }
}

impl From<&Path> for WalletPath {
    fn from(p: &Path) -> Self {
        Self(p.to_owned())
    }
}

impl Display for WalletPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
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

impl Default for Gas {
    fn default() -> Self {
        Self::new()
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

mod base64 {
    use serde::{Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64::encode(v);
        String::serialize(&base64, s)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use tempfile::tempdir;

    const TEST_ADDR: &str = "2w7fRQW23Jn9Bgm1GQW9eC2bD9U883dAwqP7HAr2F8g1syzPQaPYrxSyyVZ81yDS5C1rv9L8KjdPBsvYawSx3QCW";

    #[derive(Clone)]
    struct WalletFile {
        path: WalletPath,
        pwd: Hash,
    }

    impl SecureWalletFile for WalletFile {
        fn path(&self) -> &WalletPath {
            &self.path
        }

        fn pwd(&self) -> Hash {
            self.pwd
        }
    }

    #[test]
    fn wallet_basics() -> Result<(), Box<dyn std::error::Error>> {
        // create a wallet from a mnemonic phrase
        let mut wallet: Wallet<WalletFile> = Wallet::new("uphold stove tennis fire menu three quick apple close guilt poem garlic volcano giggle comic")?;

        // check address generation
        let default_addr = wallet.default_address();
        let other_addr = wallet.new_address();

        assert!(format!("{}", default_addr).eq(TEST_ADDR));
        assert!(default_addr.ne(&other_addr));
        assert!(wallet.address_count() == 2);

        // create another wallet with different mnemonic
        let wallet: Wallet<WalletFile> = Wallet::new("demise monitor elegant cradle squeeze cheap parrot venture stereo humor scout denial action receive flat")?;

        // check addresses are different
        let addr = wallet.default_address();
        assert!(format!("{}", addr).ne(TEST_ADDR));

        // attempt to create a wallet from an invalid mnemonic
        let bad_wallet: Result<Wallet<WalletFile>, Error> =
            Wallet::new("good luck with life");
        assert!(bad_wallet.is_err());

        Ok(())
    }

    #[test]
    fn save_and_load() -> Result<(), Box<dyn std::error::Error>> {
        // prepare a tmp path
        let dir = tempdir()?;
        let path = dir.path().join("my_wallet.dat");
        let path = WalletPath::from(path);

        // we'll need a password too
        let pwd = blake3::hash("mypassword".as_bytes());

        // create and save
        let mut wallet: Wallet<WalletFile> = Wallet::new("uphold stove tennis fire menu three quick apple close guilt poem garlic volcano giggle comic")?;
        let file = WalletFile { path, pwd };
        wallet.save_to(file.clone())?;

        // load from file and check
        let loaded_wallet = Wallet::from_file(file)?;

        let original_addr = wallet.default_address();
        let loaded_addr = loaded_wallet.default_address();
        assert!(original_addr.eq(&loaded_addr));

        Ok(())
    }

    #[test]
    fn addresses_serde() -> Result<(), Box<dyn std::error::Error>> {
        let addrs = Addresses { count: 6 };
        let read = Addresses::from_bytes(&addrs.to_bytes())?;
        assert!(read.count == addrs.count);
        Ok(())
    }
}
