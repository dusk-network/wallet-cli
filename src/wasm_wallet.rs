use dusk_pki::SecretSpendKey;
use dusk_wallet_core::{StateClient, Store, MAX_CALL_SIZE};
use phoenix_core::Note;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::clients::Prover;
use crate::dat::{self};
use crate::rusk::RuskClient;
use crate::store::LocalStore;
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
    store: LocalStore,
    file: Option<F>,
    addresses: Vec<Address>,
}

// Result we get from a wasm call
#[derive(Debug)]
struct CallResult {
    pub status: bool,
    pub ptr: u64,
    pub len: u64,
}

// holds the wasm instance
struct WalletCore {
    store: WasmStore,
    module: Module,
    instance: Instance,
}

/// Json response allocated by the wasm when calling the balance function
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct BalanceResponse {
    /// Maximum value per transaction
    pub maximum: u64,
    /// Total computed balance
    pub value: u64,
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
            module,
            instance,
        };

        Ok(Self {
            wallet_core,
            state: None,
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

        for note in &notes {
            if !ssk.view_key().owns(note) {
                println!("{:?}", "that's the problem");
            }
        }

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

    // pub fn transfer(&self) -> anyhow::Result<()> {
    //     Ok(())
    // }

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
                let mut result = Self::decompose(*result);

                println!("{:?}", result);

                let result_bytes = result.get_and_free(self)?;
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
}

impl CallResult {
    fn get_and_free(
        &mut self,
        wallet: &mut WalletCore,
    ) -> anyhow::Result<Vec<u8>> {
        let mut bytes = vec![0u8; self.len as usize];

        // if self.status {
        wallet
            .instance
            .exports
            .get_memory("memory")?
            .view(&wallet.store)
            .read(self.ptr, &mut bytes)?;

        wallet.instance.exports.get_function("free_mem")?.call(
            &mut wallet.store,
            &[Value::I32(self.ptr as i32), Value::I32(self.len as i32)],
        )?;
        // }

        println!("{:?}", bytes);

        Ok(bytes)
    }
}
