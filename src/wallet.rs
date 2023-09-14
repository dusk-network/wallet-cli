// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

/// Keeps tracks of addresses and index
pub mod address;
/// WalletFile and SecureWallet implementation
pub mod file;
/// Gas representation
pub mod gas;

mod call;
mod wallet_core;

use crate::clients::StateStore;
use crate::crypto::encrypt;
use crate::dat::{
    self, version_bytes, DatFileVersion, FILE_TYPE, LATEST_VERSION, MAGIC,
    RESERVED,
};
use crate::error::Error;
use crate::prover::Prover;
use crate::rusk::RuskClient;
use crate::store::{self, LocalStore};
use crate::wallet::wallet_core::WalletCore;
use crate::wallet::{call::CallBuilder, file::SecureWalletFile, gas::Gas};
use crate::Address;
use crate::Dusk;
use bip39::{Language, Mnemonic, Seed};
use dusk_bls12_381_sign::{PublicKey, SecretKey};
use dusk_bytes::{DeserializableSlice, Serializable};
use dusk_pki::{PublicSpendKey, ViewKey};
use dusk_plonk::prelude::BlsScalar;
use dusk_wallet_core::StakeInfo;
use dusk_wallet_core::{Store, MAX_CALL_SIZE};
use dusk_wallet_core_wasm::tx::UnprovenTransaction;
use dusk_wallet_core_wasm::types::{
    BalanceArgs, BalanceResponse, ExecuteArgs, ExecuteCall, ExecuteOutput,
    ExecuteResponse, NullifiersArgs, OutputType, ViewKeysArgs,
};
use flume::Receiver;
use phoenix_core::{Note, Transaction};
use rand::prelude::StdRng;
use rand::{Rng, SeedableRng};
use rand_core::RngCore;
use rkyv::ser::serializers::AllocSerializer;
use serde::{Deserialize, Serialize};

use std::fs::{self, read};
use std::path::Path;
use std::path::PathBuf;

/// This is exact same wallet as the one in wallet.rs but uses the wasm binary
/// to interface with wallet_core
pub struct WasmWallet<F: SecureWalletFile> {
    wallet_core: WalletCore,
    state: Option<StateStore>,
    prover: Option<Prover>,
    store: LocalStore,
    addresses: Vec<Address>,
    /// DAT File and the file version
    pub file: Option<(F, DatFileVersion)>,
    /// Recieve the status/errors of the sync procss
    pub sync_rx: Option<Receiver<String>>,
}

impl<F: SecureWalletFile> WasmWallet<F> {
    /// Creates a new wasm wallet instance by reading the given wasm binary file
    pub fn new<T: AsRef<[u8]>>(
        wasm_binary: T,
        file: F,
    ) -> anyhow::Result<Self> {
        let wallet_core = WalletCore::new(wasm_binary)?;

        let path = file.path();
        let pwd = file.pwd();

        // make sure file exists
        let pb = path.inner().clone();
        if !pb.is_file() {
            return Err(Error::WalletFileMissing.into());
        }

        // attempt to load and decode wallet
        let bytes = read(&pb)?;
        let file_version = dat::check_version(bytes.get(0..12))?;
        let (seed, address_count) =
            dat::get_seed_and_address(file_version, bytes, pwd)?;

        let store = LocalStore::new(seed);

        let addresses: Vec<_> = (0..address_count)
            .map(|i| {
                let ssk = store
                    .retrieve_ssk(i as u64)
                    .expect("wallet seed should be available");

                Address::new(i, ssk.public_spend_key())
            })
            .collect();

        Ok(Self {
            wallet_core,
            state: None,
            prover: None,
            store,
            addresses,
            file: Some((file, file_version)),
            sync_rx: None,
        })
    }

    /// Create a wallet from menmonic and wasm binary file location
    pub fn from_mnemonic<T, P>(
        wasm_binary: T,
        phrase: P,
    ) -> anyhow::Result<Self>
    where
        P: Into<String>,
        T: AsRef<[u8]>,
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
            let seed =
                store::Seed::from_reader(&mut bytes).map_err(Error::Bytes)?;

            let store = LocalStore::new(seed);

            // Generate the default address
            let ssk = store
                .retrieve_ssk(0)
                .expect("wallet seed should be available");

            let address = Address::new(0, ssk.public_spend_key());

            let wallet_core = WalletCore::new(wasm_binary)?;

            // return new wallet instance
            Ok(Self {
                wallet_core,
                addresses: vec![address],
                store,
                file: None,
                state: None,
                prover: None,
                sync_rx: None,
            })
        } else {
            Err(Error::InvalidMnemonicPhrase.into())
        }
    }

    /// Connect the wasm wallet to the node and create the state
    pub async fn connect<S: Into<String>>(
        &mut self,
        rusk_addr: S,
        prov_addr: S,
        status: fn(&str),
    ) -> Result<(), Error> {
        let rusk = RuskClient::new(rusk_addr, prov_addr);
        rusk.state.check_connection().await?;

        // create a prover client
        let mut prover = Prover::new(rusk.state.clone(), rusk.prover.clone());
        prover.set_status_callback(status);

        let cache_dir = {
            if let Some(file) = &self.file {
                file.0.path().cache_dir()
            } else {
                return Err(Error::WalletFileMissing);
            }
        };

        let state = StateStore::new(
            rusk.state,
            &cache_dir,
            self.store.clone(),
            status,
        )?;

        state.sync().await?;

        self.state = Some(state);
        self.prover = Some(prover);

        // sync as soon as we connect

        Ok(())
    }

    /// Helper function to register for async-sync outside of connect
    pub async fn register_sync(&mut self) -> anyhow::Result<()> {
        let state = self.state.as_ref().ok_or(Error::Offline)?;

        let (sync_tx, sync_rx) = flume::unbounded::<String>();

        state.register_sync(sync_tx).await?;

        self.sync_rx = Some(sync_rx);

        Ok(())
    }

    /// Saves wallet to file from which it was loaded
    pub fn save(&mut self) -> Result<(), Error> {
        match &self.file {
            Some(f) => {
                let mut header = Vec::with_capacity(12);
                header.extend_from_slice(&MAGIC.to_be_bytes());
                // File type = Rusk Wallet (0x02)
                header.extend_from_slice(&FILE_TYPE.to_be_bytes());
                // Reserved (0x0)
                header.extend_from_slice(&RESERVED.to_be_bytes());
                // Version
                header.extend_from_slice(&version_bytes(LATEST_VERSION));

                // create file payload
                let seed = self.store.get_seed()?;
                let mut payload = seed.to_vec();

                payload.push(self.addresses.len() as u8);

                // encrypt the payload
                payload = encrypt(&payload, f.0.pwd())?;

                let mut content =
                    Vec::with_capacity(header.len() + payload.len());

                content.extend_from_slice(&header);
                content.extend_from_slice(&payload);

                // write the content to file
                fs::write(&f.0.path().wallet, content)?;
                Ok(())
            }
            None => Err(Error::WalletFileMissing),
        }
    }

    /// Fetches the notes from the state.
    pub async fn get_all_notes(
        &self,
        addr: &Address,
    ) -> anyhow::Result<Vec<DecodedNote>> {
        if !addr.is_owned() {
            return Err(Error::Unauthorized.into());
        }

        let state = self.state.as_ref().ok_or(Error::Offline)?;

        let ssk_index = addr.index()? as u64;
        let ssk = self.store.retrieve_ssk(ssk_index)?;
        let vk = ssk.view_key();

        let notes = state.fetch_notes(&vk).await?;

        let nullifiers: Vec<_> =
            notes.iter().map(|(n, _)| n.gen_nullifier(&ssk)).collect();
        let existing_nullifiers =
            state.fetch_existing_nullifiers(&nullifiers[..]).await?;
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
    }

    /// Return all addresses in the wallet
    pub fn addresses(&self) -> &[Address] {
        &self.addresses
    }

    /// Calculate balance from wallet core
    pub async fn get_balance(
        &mut self,
        index: u8,
    ) -> anyhow::Result<BalanceResponse> {
        let vks = self.view_keys()?;

        let vk = vks.get::<usize>(index.into()).ok_or(Error::BadAddress)?;
        let notes = self.unspent_notes(vk).await?;

        let seed = self.store.get_seed()?.to_vec();

        let serialized = rkyv::to_bytes::<_, MAX_CALL_SIZE>(&notes)?.into_vec();

        let balance_args = BalanceArgs {
            notes: serialized,
            seed,
        };
        let result: BalanceResponse =
            to_json(self.wallet_core.call("balance", balance_args)?)?;

        Ok(result)
    }

    // Creates a new public address.
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

    /// Computes an unproven transaction.
    ///
    /// # Arguments
    ///
    /// * `call` - A contract call to make.
    ///   - `contract` - The contract to call as Base58.
    ///   - `method` - A string with the name of the method to call.
    ///   - `payload` - Arbitrary bytes to be sent to the contract.
    /// * `crossover` - A inter-contract crossover value.
    /// * `gas_limit` - The gas limit for the transaction.
    /// * `gas_price` - The gas price for the transaction.
    /// * `output` - The output note produced by the transaction.
    ///   - `type` - The type of the output note. Can be either "Transparent" or
    ///     "Obfuscated".
    ///   - `receiver` - The public spend key of the receiver on Base58 format.
    ///   - `value` - The value of the output note.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute<C>(
        &mut self,
        sender: u8,
        crossover: Option<u64>,
        call: Option<(String, String, C)>,
        output: Option<(OutputType, PublicSpendKey, u64)>,
        gas: Gas,
    ) -> anyhow::Result<Transaction>
    where
        C: rkyv::Serialize<AllocSerializer<MAX_CALL_SIZE>>,
    {
        let vks = self.view_keys()?;
        let vk = vks.get::<usize>(sender.into()).ok_or(Error::BadAddress)?;

        let sender = self
            .addresses
            .get(sender as usize)
            .ok_or(Error::BadAddress)?;

        let refund = bs58::encode(sender.psk().to_bytes()).into_string();

        let mut rng = StdRng::from_entropy();
        let mut rng_seed = [0; 64];

        rng.fill_bytes(&mut rng_seed);

        let mut openings = Vec::new();

        let notes = self.unspent_notes(vk).await?;
        let state = self.state.as_ref().ok_or(Error::Offline)?;

        for note in &notes {
            let opening = state.fetch_opening(note).await?;
            openings.push(opening);
        }

        let openings = rkyv::to_bytes::<_, MAX_CALL_SIZE>(&openings)?.to_vec();

        let inputs = rkyv::to_bytes::<_, MAX_CALL_SIZE>(&notes)?.to_vec();

        let mut args = ExecuteArgs {
            crossover,
            gas_limit: gas.limit,
            gas_price: gas.price,
            inputs,
            openings,
            refund,
            seed: self.store.get_seed()?.to_vec(),
            rng_seed: rng_seed.to_vec(),
            call: None,
            output: None,
        };

        // set call params if present
        if let Some((contract, method, payload)) = call {
            let call_data = rkyv::to_bytes(&payload)?;

            args.call = Some(ExecuteCall {
                contract,
                method,
                payload: call_data.to_vec(),
            });
        }

        // Set output
        if let Some((note_type, reciever, value)) = output {
            let receiver = bs58::encode(reciever.to_bytes()).into_string();

            args.output = Some(ExecuteOutput {
                note_type,
                receiver,
                ref_id: rng.gen(),
                value,
            });
        }

        let ExecuteResponse { tx, .. } =
            to_json(self.wallet_core.call("execute", args)?)?;

        let prover = self.prover.as_ref().ok_or(Error::Offline)?;

        if let Ok(unproven_tx) = rkyv::from_bytes::<UnprovenTransaction>(&tx) {
            Ok(prover
                .compute_proof_and_propagate_wasm(&unproven_tx)
                .await?)
        } else {
            Err(Error::WasmOutput.into())
        }
    }

    /// Transfer
    pub async fn transfer(
        &mut self,
        sender: u8,
        reciever: &Address,
        value: u64,
        gas: Gas,
    ) -> anyhow::Result<Transaction> {
        let output = (OutputType::Obfuscated, *reciever.psk(), value);

        self.execute::<()>(sender, None, None, Some(output), gas)
            .await
    }

    /// Stake
    pub async fn stake(
        &mut self,
        index: u8,
        amt: Dusk,
        gas: Gas,
    ) -> anyhow::Result<Transaction> {
        let addr = self
            .addresses
            .get(index as usize)
            .ok_or(Error::BadAddress)?;

        let refund = addr.psk();

        // make sure we own the staking address
        if !addr.is_owned() {
            return Err(Error::Unauthorized.into());
        }
        // make sure amount is positive
        if amt == 0 {
            return Err(Error::AmountIsZero.into());
        }
        // check if the gas is enough
        if !gas.is_enough() {
            return Err(Error::NotEnoughGas.into());
        }

        let state = self.state.as_ref().ok_or(Error::Offline)?;
        let prover = self.prover.as_ref().ok_or(Error::Offline)?;

        let sender = self.store.retrieve_ssk(index.into())?;
        let sk = self.store.retrieve_sk(index.into())?;
        let pk = PublicKey::from(&sk);

        let stake = state.fetch_stake(&pk).await?;

        if stake.amount.is_some() {
            return Err(Error::AlreadyStaked.into());
        }

        let value = amt.0;

        let stake = CallBuilder::new(
            &mut StdRng::from_entropy(),
            *refund,
            value,
            rusk_abi::STAKE_CONTRACT,
            sender,
        )
        .gas(&gas)
        .prove_stct(prover)
        .await?
        .get_stake(sk, pk, stake.counter);

        let call_data = rkyv::to_bytes::<_, MAX_CALL_SIZE>(&stake)?.to_vec();

        let call = Some((
            bs58::encode(rusk_abi::STAKE_CONTRACT.to_bytes()).into_string(),
            String::from("stake"),
            call_data,
        ));

        let output = (OutputType::Transparent, *refund, value);

        self.execute(index, None, call, Some(output), gas).await
    }

    /// stake allow
    pub async fn stake_allow(
        &mut self,
        index: u8,
        staker: &PublicKey,
        gas: Gas,
    ) -> anyhow::Result<Transaction> {
        let addr = self
            .addresses
            .get(index as usize)
            .ok_or(Error::BadAddress)?;

        let refund = addr.psk();

        // make sure we own the staking address
        if !addr.is_owned() {
            return Err(Error::Unauthorized.into());
        }

        // check if the gas is enough
        // TODO: This should be tuned with the right usage for this tx
        if !gas.is_enough() {
            return Err(Error::NotEnoughGas.into());
        }

        let sender = self.store.retrieve_ssk(index.into())?;
        let sk = self.store.retrieve_sk(index.into())?;
        let pk = PublicKey::from(&sk);

        let stake = self
            .state
            .as_ref()
            .ok_or(Error::Offline)?
            .fetch_stake(&pk)
            .await?;

        let allow = CallBuilder::new(
            &mut StdRng::from_entropy(),
            *refund,
            0,
            rusk_abi::STAKE_CONTRACT,
            sender,
        )
        .get_stake_allow(sk, pk, stake.counter, staker);

        let call_data = rkyv::to_bytes::<_, MAX_CALL_SIZE>(&allow)?.to_vec();

        let call = Some((
            bs58::encode(rusk_abi::STAKE_CONTRACT.to_bytes()).into_string(),
            String::from("allow"),
            call_data,
        ));

        let output = (OutputType::Transparent, *refund, 0);

        self.execute(index, None, call, Some(output), gas).await
    }

    /// Get stake-info
    pub async fn stake_info(&mut self, index: u8) -> anyhow::Result<StakeInfo> {
        Ok(self
            .state
            .as_ref()
            .ok_or(Error::Offline)?
            .fetch_stake(&PublicKey::from(
                &self.store.retrieve_sk(index.into())?,
            ))
            .await?)
    }

    /// unstake
    pub async fn unstake(
        &mut self,
        index: u8,
        gas: Gas,
    ) -> anyhow::Result<Transaction> {
        let addr = self
            .addresses
            .get(index as usize)
            .ok_or(Error::BadAddress)?;

        let index = addr.index()?;
        let refund = addr.psk();

        // make sure we own the staking address
        if !addr.is_owned() {
            return Err(Error::Unauthorized.into());
        }

        let sender = self.store.retrieve_ssk(index.into())?;
        let sk = self.store.retrieve_sk(index.into())?;
        let pk = PublicKey::from(&sk);

        let state = self.state.as_ref().ok_or(Error::Offline)?;
        let prover = self.prover.as_ref().ok_or(Error::Offline)?;

        let stake = state.fetch_stake(&pk).await?;

        let (value, _) = stake.amount.ok_or(Error::NotStaked)?;

        let unstake = CallBuilder::new(
            &mut StdRng::from_entropy(),
            *refund,
            value,
            rusk_abi::STAKE_CONTRACT,
            sender,
        )
        .gas(&gas)
        .prove_wfct(prover)
        .await?
        .get_unstake(sk, pk, stake.counter);

        let call_data = rkyv::to_bytes::<_, MAX_CALL_SIZE>(&unstake)?.to_vec();

        let call = Some((
            bs58::encode(rusk_abi::STAKE_CONTRACT.to_bytes()).into_string(),
            String::from("unstake"),
            call_data,
        ));

        let output = (OutputType::Transparent, *refund, 0);

        self.execute(index, None, call, Some(output), gas).await
    }

    /// withdraw
    pub async fn withdraw_reward(
        &mut self,
        index: u8,
        gas: Gas,
    ) -> anyhow::Result<Transaction> {
        let addr = self
            .addresses
            .get(index as usize)
            .ok_or(Error::BadAddress)?;

        let refund = addr.psk();

        // make sure we own the staking address
        if !addr.is_owned() {
            return Err(Error::Unauthorized.into());
        }

        let sender = self.store.retrieve_ssk(index.into())?;
        let sk = self.store.retrieve_sk(index.into())?;
        let pk = PublicKey::from(&sk);

        let mut rng = StdRng::from_entropy();

        let stake = self
            .state
            .as_ref()
            .ok_or(Error::Offline)?
            .fetch_stake(&pk)
            .await?;

        let unstake = CallBuilder::new(
            &mut rng,
            *refund,
            0,
            rusk_abi::STAKE_CONTRACT,
            sender,
        )
        .get_withdraw(&mut rng, pk, sk, stake.counter);

        let call_data = rkyv::to_bytes::<_, MAX_CALL_SIZE>(&unstake)?.to_vec();

        let call = Some((
            bs58::encode(rusk_abi::STAKE_CONTRACT.to_bytes()).into_string(),
            String::from("withdraw"),
            call_data,
        ));

        let output = (OutputType::Transparent, *refund, 0);

        self.execute(index, None, call, Some(output), gas).await
    }

    /// claim an address
    pub fn claim_as_address(&self, addr: Address) -> Result<&Address, Error> {
        self.addresses()
            .iter()
            .find(|a| a.psk == addr.psk)
            .ok_or(Error::AddressNotOwned)
    }

    /// Checks if the wallet has an active connection to the network
    pub fn is_online(&self) -> bool {
        self.state.is_some() && self.prover.is_some()
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

    fn view_keys(&mut self) -> anyhow::Result<Vec<ViewKey>> {
        let view_key_args = ViewKeysArgs {
            seed: self.store.get_seed()?.to_vec(),
        };

        let view_keys: Vec<u8> =
            self.wallet_core.call("view_keys", view_key_args)?;

        if let Ok(view_keys) = rkyv::from_bytes(&view_keys) {
            Ok(view_keys)
        } else {
            Err(anyhow::anyhow!(
                "Failed to get view keys for seed from wallet-core"
            ))
        }
    }

    async fn unspent_notes(
        &mut self,
        vk: &ViewKey,
    ) -> anyhow::Result<Vec<Note>> {
        let state = self.state.as_ref().ok_or(Error::Offline)?;

        let notes = state
            .fetch_notes(vk)
            .await?
            .into_iter()
            .map(|(notes, _)| notes)
            .collect();

        let nullifiers: Vec<u8> = self.wallet_core.call(
            "nullifiers",
            NullifiersArgs {
                notes: rkyv::to_bytes::<Vec<Note>, MAX_CALL_SIZE>(&notes)?
                    .to_vec(),
                seed: self.store.get_seed()?.to_vec(),
            },
        )?;

        if let Ok(nullifiers) = rkyv::from_bytes::<Vec<BlsScalar>>(&nullifiers)
        {
            let existing_nullifiers =
                state.fetch_existing_nullifiers(&nullifiers).await?;

            let unspent_notes = notes
                .into_iter()
                .zip(nullifiers.into_iter())
                .filter(|(_, nullifier)| {
                    !existing_nullifiers.contains(nullifier)
                })
                .map(|(note, _)| note)
                .collect();

            Ok(unspent_notes)
        } else {
            Err(anyhow::anyhow!("Failed fetch nullifiers from wallet-core"))
        }
    }

    /// Return the dat file version from memory or by reading the file
    /// In order to not read the file version more than once per execution
    pub fn get_file_version(&self) -> Result<DatFileVersion, Error> {
        if let Some((_, version)) = &self.file {
            Ok(*version)
        } else {
            Err(Error::WalletFileMissing)
        }
    }

    /// Save to a particular location
    pub fn save_to(&mut self, file: F) -> anyhow::Result<(), Error> {
        // set our new file and save
        self.file =
            Some((file, DatFileVersion::RuskBinaryFileFormat(LATEST_VERSION)));
        self.save()
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

fn to_json<D>(bytes: Vec<u8>) -> anyhow::Result<D>
where
    D: for<'a> Deserialize<'a>,
{
    let json = String::from_utf8(bytes)?;
    Ok(serde_json::from_str(&json)?)
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
    use super::{WasmWallet as Wallet, *};
    use crate::WalletPath;

    use tempfile::tempdir;

    const WASM_WALLET: &[u8] = include_bytes!("../assets/mod.wasm");
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
        let mut wallet: Wallet<WalletFile> = Wallet::from_mnemonic(WASM_WALLET, "uphold stove tennis fire menu three quick apple close guilt poem garlic volcano giggle comic")?;

        // check address generation
        let default_addr = wallet.default_address().clone();
        let other_addr = wallet.new_address();

        assert!(format!("{}", default_addr).eq(TEST_ADDR));
        assert_ne!(&default_addr, other_addr);
        assert_eq!(wallet.addresses.len(), 2);

        // create another wallet with different mnemonic
        let wallet: Wallet<WalletFile> = Wallet::from_mnemonic(WASM_WALLET, "demise monitor elegant cradle squeeze cheap parrot venture stereo humor scout denial action receive flat")?;

        // check addresses are different
        let addr = wallet.default_address();
        assert!(format!("{}", addr).ne(TEST_ADDR));

        // attempt to create a wallet from an invalid mnemonic
        let bad_wallet: anyhow::Result<Wallet<WalletFile>> =
            Wallet::from_mnemonic("assets/mod.wasm", "good luck with life");
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
        let pwd = blake3::hash("mypassword".as_bytes()).as_bytes().to_vec();

        // create and save
        let mut wallet: Wallet<WalletFile> = Wallet::from_mnemonic(WASM_WALLET, "uphold stove tennis fire menu three quick apple close guilt poem garlic volcano giggle comic")?;
        let file = WalletFile { path, pwd };
        wallet.save_to(file.clone())?;

        // load from file and check
        let loaded_wallet = Wallet::new(WASM_WALLET, file)?;

        let original_addr = wallet.default_address();
        let loaded_addr = loaded_wallet.default_address();
        assert!(original_addr.eq(loaded_addr));

        Ok(())
    }
}
