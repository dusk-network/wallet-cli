// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use dusk_pki::{PublicSpendKey, SecretSpendKey};
use dusk_wallet_core::{StateClient, Store, MAX_CALL_SIZE};
use dusk_wallet_core_wasm::tx::{CallData, UnprovenTransaction};
use phoenix_core::{Note, Transaction};
use rand::prelude::StdRng;
use rand::SeedableRng;
use rand_core::RngCore;
use rkyv::ser::serializers::AllocSerializer;
use rusk_abi::ContractId;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::clients::Prover;
use crate::dat::{self};
use crate::gas::Gas;
use crate::rusk::RuskClient;
use crate::store::LocalStore;
use dusk_wallet_core_wasm::types::{
    BalanceResponse, ExecuteArgs, ExecuteCall, ExecuteOutput, ExecuteResponse,
    OutputType,
};

use crate::SecureWalletFile;
use crate::{Address, Error};
use std::fs::read;
use std::path::Path;

use wasmer::{imports, Instance, Module, Store as WasmStore, Value};

use crate::clients::StateStore;

/// This is exact same wallet as the one in wallet.rs but uses the wasm binary
/// to interface with wallet_core
pub struct WasmWallet<F: SecureWalletFile> {
    wallet_core: WalletCore,
    state: Option<StateStore>,
    prover: Option<Prover>,
    store: LocalStore,
    file: Option<F>,
    addresses: Vec<Address>,
}

// holds the wasm instance
struct WalletCore {
    store: WasmStore,
    instance: Instance,
}

impl<F: SecureWalletFile> WasmWallet<F> {
    /// Creates a new wasm wallet instance by reading the given wasm binary file
    pub fn new<T: AsRef<Path>>(
        wasm_binary: T,
        file: F,
    ) -> anyhow::Result<Self> {
        let bytes = read(wasm_binary)?;

        let mut wasm_store = WasmStore::default();
        let module = Module::new(&wasm_store, bytes)?;

        let import_object = imports! {};
        let instance = Instance::new(&mut wasm_store, &module, &import_object)?;

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

        let wallet_core = WalletCore {
            store: wasm_store,
            instance,
        };

        Ok(Self {
            wallet_core,
            state: None,
            prover: None,
            store,
            addresses,
            file: Some(file),
        })
    }

    /// Connect the wasm wallet to the node and create the state
    pub async fn connect<S: Into<String>>(
        &mut self,
        rusk_addr: S,
        prov_addr: S,
        status: fn(&str),
    ) -> anyhow::Result<()> {
        let rusk = RuskClient::new(rusk_addr, prov_addr);
        rusk.state.check_connection().await?;

        // create a prover client
        let mut prover = Prover::new(rusk.state.clone(), rusk.prover.clone());
        prover.set_status_callback(status);

        let cache_dir = {
            if let Some(file) = &self.file {
                file.path().cache_dir()
            } else {
                return Err(Error::WalletFileMissing.into());
            }
        };

        let state = StateStore::new(
            rusk.state,
            &cache_dir,
            self.store.clone(),
            status,
        )?;

        self.state = Some(state);
        self.prover = Some(prover);

        Ok(())
    }

    /// Return all addresses in the wallet
    pub fn addresses(&self) -> &[Address] {
        &self.addresses
    }

    /// Calculate balance from wallet core
    pub fn get_balance(
        &mut self,
        addr: &Address,
    ) -> anyhow::Result<BalanceResponse> {
        let index = addr.index()?;
        let ssk = self.store.retrieve_ssk(index.into())?;

        let notes = self.unspent_notes(&ssk)?;

        let seed = self.store.get_seed()?.to_vec();

        let serialized = rkyv::to_bytes::<_, MAX_CALL_SIZE>(&notes)?.into_vec();

        let result: BalanceResponse = self.wallet_core.call(
            "balance",
            json!({
                "notes": serialized,
                "seed": seed
            }),
        )?;

        Ok(result)
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
    ///   - `ref_id` - The reference ID to be appended to the output note.
    ///   - `value` - The value of the output note.
    #[allow(clippy::too_many_arguments)]
    pub fn execute<C>(
        &mut self,
        sender: &Address,
        crossover: Option<u64>,
        call: Option<(String, String, C)>,
        output: Option<(OutputType, PublicSpendKey, u64, u64)>,
        gas: Gas,
    ) -> anyhow::Result<Transaction>
    where
        C: rkyv::Serialize<AllocSerializer<MAX_CALL_SIZE>>,
    {
        let state = self.state.as_ref().ok_or(Error::Offline)?;
        let prover = self.prover.as_ref().ok_or(Error::Offline)?;
        let ssk = self.store.retrieve_ssk(sender.index()?.into())?;
        let notes = self.unspent_notes(&ssk)?;

        let inputs = rkyv::to_bytes::<_, MAX_CALL_SIZE>(&notes)?.to_vec();

        let mut rng = StdRng::from_entropy();
        let mut rng_seed = [0; 64];

        rng.fill_bytes(&mut rng_seed);

        let mut openings = Vec::new();

        for note in notes {
            let opening = state.fetch_opening(&note)?;
            openings.push(opening);
        }

        let openings = rkyv::to_bytes::<_, MAX_CALL_SIZE>(&openings)?.to_vec();

        let refund = bs58::encode(sender.psk().to_bytes()).into_string();

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
        if let Some((note_type, reciever, ref_id, value)) = output {
            let receiver = bs58::encode(reciever.to_bytes()).into_string();

            args.output = Some(ExecuteOutput {
                note_type,
                receiver,
                ref_id: Some(ref_id),
                value,
            });
        }

        let ExecuteResponse { tx, .. } =
            self.wallet_core.call("execute", args)?;

        if let Ok(tx) = rkyv::from_bytes::<UnprovenTransaction>(&tx) {
            Ok(prover.compute_proof_and_propagate_wasm(&tx)?)
        } else {
            Err(Error::WasmOutput.into())
        }
    }

    /// Transfer
    pub fn transfer(
        &mut self,
        sender: &Address,
        reciever: &Address,
        ref_id: u64,
        value: u64,
        gas: Gas,
    ) -> anyhow::Result<Transaction> {
        let output = (OutputType::Transparent, *reciever.psk(), ref_id, value);

        self.execute::<()>(sender, None, None, Some(output), gas)
    }

    fn unspent_notes(&self, ssk: &SecretSpendKey) -> anyhow::Result<Vec<Note>> {
        let vk = ssk.view_key();

        let state = self.state.as_ref().ok_or(Error::Offline)?;

        let notes = state.fetch_notes(&vk)?;

        let nullifiers: Vec<_> =
            notes.iter().map(|(n, _)| n.gen_nullifier(ssk)).collect();

        let existing_nullifiers =
            state.fetch_existing_nullifiers(&nullifiers)?;

        let unspent_notes = notes
            .into_iter()
            .zip(nullifiers.into_iter())
            .filter(|(_, nullifier)| !existing_nullifiers.contains(nullifier))
            .map(|((note, _), _)| note)
            .collect();

        Ok(unspent_notes)
    }
}

impl WalletCore {
    fn call<T, R>(&mut self, f: &str, args: T) -> anyhow::Result<R>
    where
        T: Serialize,
        R: for<'a> Deserialize<'a>,
    {
        let bytes = serde_json::to_string(&args)?;
        let len = Value::I32(bytes.len() as i32);
        let malloc = self
            .instance
            .exports
            .get_function("malloc")?
            .call(&mut self.store, &[len.clone()])?;

        if let Some(Value::I32(ptr)) = malloc.get(0) {
            self.instance
                .exports
                .get_memory("memory")?
                .view(&self.store)
                .write(*ptr as u64, bytes.as_bytes())?;

            let ptr = Value::I32(*ptr);

            if let Some(Value::I64(result)) = self
                .instance
                .exports
                .get_function(f)?
                .call(&mut self.store, &[ptr, len])?
                .get(0)
            {
                let result = Self::decompose(*result);

                let result_bytes = self.get_and_free(result)?;
                let json = String::from_utf8(result_bytes)?;
                let result_json = serde_json::from_str(&json)?;

                return Ok(result_json);
            }
        }

        Err(Error::WasmMemory.into())
    }

    // Decomposes a `i64` into its inner arguments, being:
    //
    // - status: a boolean indicating the success of the operation
    // - ptr: a pointer to the underlying data
    // - len: the length of the underlying data
    fn decompose(result: i64) -> CallResult {
        let ptr = (result >> 32) as u64;
        let len = ((result << 32) >> 48) as u64;
        let status = ((result << 63) >> 63) == 0;

        CallResult { status, ptr, len }
    }

    fn get_and_free(
        &mut self,
        CallResult { status, ptr, len }: CallResult,
    ) -> anyhow::Result<Vec<u8>> {
        let mut bytes = vec![0u8; len as usize];

        if status {
            self.instance
                .exports
                .get_memory("memory")?
                .view(&self.store)
                .read(ptr, &mut bytes)?;

            self.instance.exports.get_function("free_mem")?.call(
                &mut self.store,
                &[Value::I32(ptr as i32), Value::I32(len as i32)],
            )?;
        }

        Ok(bytes)
    }
}

#[derive(Debug)]
struct CallResult {
    status: bool,
    ptr: u64,
    len: u64,
}
