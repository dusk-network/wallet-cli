// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod address;
mod file;
pub mod gas;

pub use address::Address;
use dusk_plonk::prelude::BlsScalar;
pub use file::{SecureWalletFile, WalletPath};

use bip39::{Language, Mnemonic, Seed};
use dusk_bytes::{DeserializableSlice, Serializable};
use phoenix_core::transaction::ModuleId;
use phoenix_core::Note;
use rkyv::ser::serializers::AllocSerializer;
use serde::Serialize;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};

use dusk_bls12_381_sign::{PublicKey, SecretKey};
use dusk_wallet_core::{
    BalanceInfo, StakeInfo, StateClient, Store, Transaction,
    Wallet as WalletCore, MAX_CALL_SIZE,
};
use rand::prelude::StdRng;
use rand::SeedableRng;

use crate::clients::{Prover, StateStore};
use crate::crypto::{decrypt, encrypt};
use crate::currency::Dusk;
use crate::rusk::{RuskClient, RuskEndpoint};
use crate::store::LocalStore;
use crate::Error;
use gas::Gas;

use crate::store;

/// Binary prefix for Dusk wallet files
const MAGIC: u32 = 0x1d0c15;
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
pub struct Wallet<F: SecureWalletFile + Debug> {
    wallet: Option<WalletCore<LocalStore, StateStore, Prover>>,
    addresses: Vec<Address>,
    store: LocalStore,
    file: Option<F>,
    status: fn(status: &str),
}

impl<F: SecureWalletFile + Debug> Wallet<F> {
    /// Returns the file used for the wallet
    pub fn file(&self) -> &Option<F> {
        &self.file
    }
}

impl<F: SecureWalletFile + Debug> Wallet<F> {
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
            // derive the mnemonic seed
            let seed = Seed::new(&mnemonic, "");
            // Takes the mnemonic seed as bytes
            let mut bytes = seed.as_bytes();

            // Generate a Store Seed type from the mnemonic Seed bytes
            let seed = store::Seed::from_reader(&mut bytes)?;

            let store = LocalStore::new(seed);

            // Generate the default address
            let ssk = store
                .retrieve_ssk(0)
                .expect("wallet seed should be available");

            let address = Address::new(0, ssk.public_spend_key());

            // return new wallet instance
            Ok(Wallet {
                wallet: None,
                addresses: vec![address],
                store,
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
        let magic =
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()) & 0x00ffffff;

        if magic != MAGIC {
            return Self::from_legacy_file(file);
        }

        bytes.drain(..3);

        // check for version information
        let [major, minor] = [bytes[0], bytes[1]];
        bytes.drain(..2);

        // decrypt and interpret file contents
        let result: Result<(store::Seed, u8), Error> = match (major, minor) {
            (1, 0) => {
                bytes = decrypt(&bytes, pwd)?;

                let seed = store::Seed::from_reader(&mut &bytes[..])
                    .map_err(|_| Error::WalletFileCorrupted)?;

                Ok((seed, 1))
            }
            (2, 0) => {
                let content = decrypt(&bytes, pwd)?;
                let mut buff = &content[..];

                // extract seed
                let seed = store::Seed::from_reader(&mut buff)
                    .map_err(|_| Error::WalletFileCorrupted)?;

                // extract addresses count
                Ok((seed, buff[0]))
            }
            _ => {
                return Err(Error::UnknownFileVersion(major, minor));
            }
        };

        let (seed, address_count) = result?;

        let store = LocalStore::new(seed);

        let addresses: Vec<_> = (0..address_count)
            .map(|i| {
                let ssk = store
                    .retrieve_ssk(i as u64)
                    .expect("wallet seed should be available");

                Address::new(i, ssk.public_spend_key())
            })
            .collect();

        // create and return
        Ok(Self {
            wallet: None,
            addresses,
            store,
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

        // get our seed
        let seed = store::Seed::from_reader(&mut &bytes[..])
            .map_err(|_| Error::WalletFileCorrupted)?;

        let store = LocalStore::new(seed);
        let ssk = store
            .retrieve_ssk(0)
            .expect("wallet seed should be available");

        let address = Address::new(0, ssk.public_spend_key());

        // return the store
        Ok(Self {
            wallet: None,
            addresses: vec![address],
            store,
            file: Some(file),
            status: |_| {},
        })
    }

    /// Saves wallet to file from which it was loaded
    pub fn save(&mut self) -> Result<(), Error> {
        match &self.file {
            Some(f) => {
                let mut header = Vec::with_capacity(5);
                header.extend_from_slice(&MAGIC.to_le_bytes()[..3]);
                header.extend_from_slice(VERSION);

                // create file payload
                let seed = self.store.get_seed()?;
                let mut payload = seed.to_vec();
                payload.push(self.addresses.len() as u8);

                // encrypt the payload
                payload = encrypt(&payload, f.pwd())?;

                let mut content =
                    Vec::with_capacity(header.len() + payload.len());

                content.extend_from_slice(&header);
                content.extend_from_slice(&payload);

                // write the content to file
                fs::write(&f.path().wallet, content)?;
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

        let cache_dir = {
            if let Some(file) = &self.file {
                file.path().cache_dir()
            } else {
                return Err(Error::WalletFileMissing);
            }
        };

        // create a state client
        let mut state =
            StateStore::new(rusk.state, &cache_dir, self.store.clone())?;

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

    /// Fetches the notes from the state.
    pub fn get_all_notes(
        &self,
        addr: &Address,
    ) -> Result<Vec<DecodedNote>, Error> {
        if !addr.is_owned() {
            return Err(Error::Unauthorized);
        }
        if let Some(wallet) = &self.wallet {
            let ssk_index = addr.index()? as u64;
            let ssk = self.store.retrieve_ssk(ssk_index).unwrap();
            let vk = ssk.view_key();

            let notes = wallet.state().fetch_notes(&vk).unwrap();

            let nullifiers: Vec<_> =
                notes.iter().map(|(n, _)| n.gen_nullifier(&ssk)).collect();
            let existing_nullifiers =
                wallet.state().fetch_existing_nullifiers(&nullifiers[..])?;
            let history = notes
                .into_iter()
                .zip(nullifiers)
                .map(|((note, block_height), nullifier)| {
                    let nullified_by = existing_nullifiers
                        .contains(&nullifier)
                        .then_some(nullifier);
                    let amount = note.value(Some(&vk)).unwrap();
                    DecodedNote {
                        note,
                        amount,
                        block_height,
                        nullified_by,
                    }
                })
                .collect();
            Ok(history)
        } else {
            Err(Error::Offline)
        }
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
            let index = addr.index()? as u64;
            Ok(wallet.get_balance(index)?)
        } else {
            Err(Error::Offline)
        }
    }

    /// Creates a new public address.
    /// The addresses generated are deterministic across sessions.
    pub fn new_address(&mut self) -> &Address {
        let len = self.addresses.len();
        let ssk = self
            .store
            .retrieve_ssk(len as u64)
            .expect("wallet seed should be available");
        let addr = Address::new(len as u8, ssk.public_spend_key());

        self.addresses.push(addr);
        self.addresses.last().unwrap()
    }

    /// Default public address for this wallet
    pub fn default_address(&self) -> &Address {
        &self.addresses[0]
    }

    /// Addresses that have been generated by the user
    pub fn addresses(&self) -> &Vec<Address> {
        &self.addresses
    }

    /// Executes a generic contract call
    pub async fn execute<C>(
        &self,
        sender: &Address,
        contract_id: ModuleId,
        call_name: String,
        call_data: C,
        gas: Gas,
    ) -> Result<Transaction, Error>
    where
        C: rkyv::Serialize<AllocSerializer<MAX_CALL_SIZE>>,
    {
        if let Some(wallet) = &self.wallet {
            // make sure we own the sender address
            if !sender.is_owned() {
                return Err(Error::Unauthorized);
            }

            // check gas limits
            if !gas.is_enough() {
                return Err(Error::NotEnoughGas);
            }

            let mut rng = StdRng::from_entropy();
            let sender_index =
                sender.index().expect("owned address should have an index");

            // transfer
            let tx = wallet.execute(
                &mut rng,
                contract_id.into(),
                call_name,
                call_data,
                sender_index as u64,
                sender.psk(),
                gas.limit,
                gas.price,
            )?;
            Ok(tx)
        } else {
            Err(Error::Offline)
        }
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
            if !gas.is_enough() {
                return Err(Error::NotEnoughGas);
            }

            let mut rng = StdRng::from_entropy();
            let ref_id = BlsScalar::random(&mut rng);
            let sender_index =
                sender.index().expect("owned address should have an index");

            // transfer
            let tx = wallet.transfer(
                &mut rng,
                sender_index as u64,
                sender.psk(),
                rcvr.psk(),
                *amt,
                gas.limit,
                gas.price,
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
            // check if the gas is enough
            if !gas.is_enough() {
                return Err(Error::NotEnoughGas);
            }

            let mut rng = StdRng::from_entropy();
            let sender_index = addr.index()?;

            // stake
            let tx = wallet.stake(
                &mut rng,
                sender_index as u64,
                sender_index as u64,
                addr.psk(),
                *amt,
                gas.limit,
                gas.price,
            )?;
            Ok(tx)
        } else {
            Err(Error::Offline)
        }
    }

    /// Allow a `staker` BLS key to stake
    pub async fn stake_allow(
        &self,
        addr: &Address,
        staker: &PublicKey,
        gas: Gas,
    ) -> Result<Transaction, Error> {
        if let Some(wallet) = &self.wallet {
            // make sure we own the staking address
            if !addr.is_owned() {
                return Err(Error::Unauthorized);
            }

            // check if the gas is enough
            // TODO: This should be tuned with the right usage for this tx
            if !gas.is_enough() {
                return Err(Error::NotEnoughGas);
            }

            let mut rng = StdRng::from_entropy();
            let index = addr.index()? as u64;

            let tx = wallet.allow(
                &mut rng,
                index,
                index,
                addr.psk(),
                staker,
                gas.limit,
                gas.price,
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
            let index = addr.index()? as u64;
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
            let index = addr.index()? as u64;

            let tx = wallet.unstake(
                &mut rng,
                index,
                index,
                addr.psk(),
                gas.limit,
                gas.price,
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
        gas: Gas,
    ) -> Result<Transaction, Error> {
        if let Some(wallet) = &self.wallet {
            // make sure we own the staking address
            if !addr.is_owned() {
                return Err(Error::Unauthorized);
            }

            let mut rng = StdRng::from_entropy();
            let index = addr.index()? as u64;

            let tx = wallet.withdraw(
                &mut rng,
                index,
                index,
                addr.psk(),
                gas.limit,
                gas.price,
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

        let index = addr.index()? as u64;

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
        pwd: &[u8],
    ) -> Result<(PathBuf, PathBuf), Error> {
        // we're expecting a directory here
        if !dir.is_dir() {
            return Err(Error::NotDirectory);
        }

        // get our keys for this address
        let keys = self.provisioner_keys(addr)?;

        // set up the path
        let mut path = PathBuf::from(dir);
        path.push(addr.to_string());

        // export public key to disk
        let bytes = keys.0.to_bytes();
        fs::write(path.with_extension("cpk"), bytes)?;

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
        fs::write(path.with_extension("keys"), bytes)?;

        Ok((path.with_extension("keys"), path.with_extension("cpk")))
    }

    /// Obtain the owned `Address` for a given address
    pub fn claim_as_address(&self, addr: Address) -> Result<&Address, Error> {
        self.addresses()
            .iter()
            .find(|a| a.psk == addr.psk)
            .ok_or(Error::AddressNotOwned)
    }
}

/// This structs represent a Note decoded enriched with useful chain information
pub struct DecodedNote {
    /// The phoenix note
    pub note: Note,
    /// The decoded amount
    pub amount: u64,
    /// The block height
    pub block_height: u64,
    /// Nullified by
    pub nullified_by: Option<BlsScalar>,
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

    use crate::crypto::password_hash;

    use tempfile::tempdir;

    const TEST_ADDR: &str = "2w7fRQW23Jn9Bgm1GQW9eC2bD9U883dAwqP7HAr2F8g1syzPQaPYrxSyyVZ81yDS5C1rv9L8KjdPBsvYawSx3QCW";

    #[derive(Debug, Clone)]
    struct WalletFile {
        path: WalletPath,
        pwd: Vec<u8>,
    }

    impl SecureWalletFile for WalletFile {
        fn path(&self) -> &WalletPath {
            &self.path
        }

        fn pwd(&self) -> &[u8] {
            &self.pwd
        }
    }

    #[test]
    fn wallet_basics() -> Result<(), Box<dyn std::error::Error>> {
        // create a wallet from a mnemonic phrase
        let mut wallet: Wallet<WalletFile> = Wallet::new("uphold stove tennis fire menu three quick apple close guilt poem garlic volcano giggle comic")?;

        // check address generation
        let default_addr = wallet.default_address().clone();
        let other_addr = wallet.new_address();

        assert!(format!("{}", default_addr).eq(TEST_ADDR));
        assert_ne!(&default_addr, other_addr);
        assert_eq!(wallet.addresses.len(), 2);

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
        let pwd = password_hash(b"mypassword").to_vec();

        // create and save
        let mut wallet: Wallet<WalletFile> = Wallet::new("uphold stove tennis fire menu three quick apple close guilt poem garlic volcano giggle comic")?;
        let file = WalletFile { path, pwd };
        wallet.save_to(file.clone())?;

        // load from file and check
        let loaded_wallet = Wallet::from_file(file)?;

        let original_addr = wallet.default_address();
        let loaded_addr = loaded_wallet.default_address();
        assert!(original_addr.eq(loaded_addr));

        Ok(())
    }
}
