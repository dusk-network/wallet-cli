// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! A client to the wallet-core library

use std::fs;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use wasmer::{imports, Instance, Module, Store, Value};

/// A client to the wallet-core library
#[derive(Debug)]
pub struct Client {
    store: Store,
    instance: Instance,
}

/// A balance struct returned by the wallet-core
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Balance {
    /// Balance value.
    pub value: u64,
    /// Maximum transfer allowed per transaction, given the current state of
    /// notes.
    pub maximum_transfer: u64,
}

/// A response to an execute request to the wallet-core library
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Execute {
    /// The serialized unproven transaction
    pub tx: Vec<u8>,
    /// The new state of unspent notes after the unproven transaction was
    /// generated
    pub unspent_notes: Vec<u8>,
}

impl Client {
    /// Instantiates the client with the provided wallet-core WASM file.
    pub fn new<W>(wallet: W) -> Result<Self>
    where
        W: AsRef<Path>,
    {
        tracing::debug!(
            "loading wallet-core from `{}`...",
            wallet.as_ref().display()
        );
        let wallet = fs::read(wallet)?;
        tracing::debug!("wallet-core found; loading wasm module...");

        let mut store = Store::default();
        let module = Module::new(&store, wallet)?;

        let import_object = imports! {};
        let instance = Instance::new(&mut store, &module, &import_object)?;

        tracing::debug!("wasm modules loaded");

        Ok(Self { store, instance })
    }

    /// Returns the secret keys seed from the provided passphrase.
    pub fn seed<P>(&mut self, passphrase: P) -> Result<Vec<u8>>
    where
        P: AsRef<[u8]>,
    {
        tracing::debug!("requesting passphrase from wallet-core...");

        let f = "seed";
        let args = json!({
            "passphrase": passphrase.as_ref()
        });
        self.call(f, args)
            .and_then(|response| self.take_bytes(response))
            .map(|seed| {
                tracing::debug!("passphrase received");
                seed
            })
    }

    /// Computes the balance of the wallet from its current state.
    pub fn balance<S, N>(&mut self, seed: S, notes: N) -> Result<Balance>
    where
        S: AsRef<[u8]>,
        N: AsRef<[u8]>,
    {
        tracing::debug!("requesting balance from wallet-core...");

        let f = "balance";
        let args = json!({
            "notes": notes.as_ref(),
            "seed": seed.as_ref(),
        });
        let response: Json = self
            .call(f, args)
            .and_then(|response| self.take_contents(response))?;

        let value = response
            .get("value")
            .ok_or(anyhow::anyhow!("value expected from balance request"))?
            .as_u64()
            .ok_or(anyhow::anyhow!(
                "u64 value expected from balance request"
            ))?;

        let maximum_transfer = response
            .get("maximum")
            .ok_or(anyhow::anyhow!(
                "maximum transfer value expected from balance request"
            ))?
            .as_u64()
            .ok_or(anyhow::anyhow!(
                "u64 maximum transfer value expected from balance request"
            ))?;

        tracing::debug!("balance of {} received", value);

        Ok(Balance {
            value,
            maximum_transfer,
        })
    }

    /// Computes an unproven transaction.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed from the passphrase of the wallet. Must be 64 bytes
    ///   long.
    /// * `rng` - A random number generator seed. Must be 64 bytes long.
    /// * `call` - A contract call to make.
    ///   - `contract` - The contract to call as Base58.
    ///   - `method` - A string with the name of the method to call.
    ///   - `payload` - Arbitrary bytes to be sent to the contract.
    /// * `crossover` - A inter-contract crossover value.
    /// * `gas_limit` - The gas limit for the transaction.
    /// * `gas_price` - The gas price for the transaction.
    /// * `inputs` - The input notes consumed by the transaction.
    /// * `openings` - The Merkle openings from the inputs to a state root of
    ///   the chain.
    /// * `output` - The output note produced by the transaction.
    ///   - `type` - The type of the output note. Can be either "Transparent" or
    ///     "Obfuscated".
    ///   - `receiver` - The public spend key of the receiver on Base58 format.
    ///   - `ref_id` - The reference ID to be appended to the output note.
    ///   - `value` - The value of the output note.
    /// * `refund` - The refund address in Base58 format.
    pub fn execute<
        S,
        R,
        Contract,
        Method,
        Payload,
        Inputs,
        Openings,
        Type,
        Receiver,
        Refund,
    >(
        &mut self,
        seed: S,
        rng: R,
        call: Option<(Contract, Method, Payload)>,
        crossover: Option<u64>,
        gas_limit: u64,
        gas_price: u64,
        inputs: Inputs,
        openings: Openings,
        output: Option<(Type, Receiver, u64, u64)>,
        refund: Refund,
    ) -> Result<Execute>
    where
        S: AsRef<[u8]>,
        R: AsRef<[u8]>,
        Contract: AsRef<str>,
        Method: AsRef<str>,
        Payload: AsRef<[u8]>,
        Inputs: AsRef<[u8]>,
        Openings: AsRef<[u8]>,
        Type: AsRef<str>,
        Receiver: AsRef<str>,
        Refund: AsRef<str>,
    {
        tracing::debug!("requesting a transaction from wallet-core...");

        let mut args = json!({
            "gas_limit": gas_limit,
            "gas_price": gas_price,
            "inputs": inputs.as_ref(),
            "openings": openings.as_ref(),
            "refund": refund.as_ref(),
            "rng_seed": rng.as_ref(),
            "seed": seed.as_ref()
        });

        if let Some((contract, method, payload)) = call {
            args["call"] = json!({
                "contract": contract.as_ref(),
                "method": method.as_ref(),
                "payload": payload.as_ref(),
            });
        }

        if let Some(crossover) = crossover {
            args["crossover"] = crossover.into();
        }

        if let Some((r#type, receiver, ref_id, value)) = output {
            args["output"] = json!({
                "note_type": r#type.as_ref(),
                "receiver": receiver.as_ref(),
                "ref_id": ref_id,
                "value": value,
            });
        }

        let f = "execute";
        let response: Json = self
            .call(f, args)
            .and_then(|response| self.take_contents(response))?;

        let tx = response
            .get("tx")
            .ok_or(anyhow::anyhow!("tx expected from execute"))
            .and_then(value_to_bytes)?;

        let unspent_notes = response
            .get("unspent")
            .ok_or(anyhow::anyhow!("unspent notes expected from execute"))
            .and_then(value_to_bytes)?;

        tracing::debug!("transaction received");

        Ok(Execute { tx, unspent_notes })
    }

    /// Merge the provided serialized notes into a single, unique list.
    pub fn merge_notes<I, N>(&mut self, notes: I) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = N>,
        N: AsRef<[u8]>,
    {
        tracing::debug!("merging notes in wallet-core...");

        let notes: Vec<_> =
            notes.into_iter().map(|n| n.as_ref().to_vec()).collect();

        let f = "merge_notes";
        let args = json!({
            "notes": notes,
        });
        self.call(f, args)
            .and_then(|response| self.take_bytes(response))
            .map(|notes| {
                tracing::debug!("notes merged");
                notes
            })
    }

    /// Filters the provided notes based on the provided flags.
    ///
    /// The two lists are expected to be of same size, and the result will
    /// contain the notes with a corresponding `false` flag. This is
    /// expected to be used to filter non-existing nullifiers;
    /// hence, unspent notes.
    pub fn filter_notes<F, N>(&mut self, flags: F, notes: N) -> Result<Vec<u8>>
    where
        F: AsRef<[bool]>,
        N: AsRef<[u8]>,
    {
        tracing::debug!("filtering notes in wallet-core...");

        let f = "filter_notes";
        let args = json!({
            "flags": flags.as_ref(),
            "notes": notes.as_ref(),
        });
        self.call(f, args)
            .and_then(|response| self.take_bytes(response))
            .map(|notes| {
                tracing::debug!("notes filtered");
                notes
            })
    }

    /// Returns all the available public spend keys to this wallet.
    pub fn public_spend_keys<S>(&mut self, seed: S) -> Result<Vec<String>>
    where
        S: AsRef<[u8]>,
    {
        tracing::debug!("requesting the public spend keys from wallet-core...");

        let f = "public_spend_keys";
        let args = json!({
            "seed": seed.as_ref(),
        });
        let response: Json = self
            .call(f, args)
            .and_then(|response| self.take_contents(response))?;

        let keys = response
            .get("keys")
            .ok_or(anyhow::anyhow!(
                "keys expected from public_spend_keys request"
            ))?
            .as_array()
            .ok_or(anyhow::anyhow!(
                "array of keys expected from public_spend_keys request"
            ))?
            .iter()
            .map(|k| {
                k.as_str().map(|k| k.to_string()).ok_or(anyhow::anyhow!(
                    "string key expected from public_spend_keys request"
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        tracing::debug!("public spend keys received");

        Ok(keys)
    }

    /// Returns all the available view keys to this wallet.
    pub fn view_keys<S>(&mut self, seed: S) -> Result<Vec<u8>>
    where
        S: AsRef<[u8]>,
    {
        tracing::debug!("requesting the view keys from wallet-core...");

        let f = "view_keys";
        let args = json!({
            "seed": seed.as_ref(),
        });
        self.call(f, args)
            .and_then(|response| self.take_bytes(response))
            .map(|keys| {
                tracing::debug!("view keys received");
                keys
            })
    }

    /// Computes the nullifiers of the provided notes using the secret seed of
    /// the wallet.
    pub fn nullifiers<S, N>(&mut self, seed: S, notes: N) -> Result<Vec<u8>>
    where
        S: AsRef<[u8]>,
        N: AsRef<[u8]>,
    {
        tracing::debug!("requesting nullifiers from wallet-core...");

        let f = "nullifiers";
        let args = json!({
            "seed": seed.as_ref(),
            "notes": notes.as_ref(),
        });
        self.call(f, args)
            .and_then(|response| self.take_bytes(response))
            .map(|nullifiers| {
                tracing::debug!("nullifiers received");
                nullifiers
            })
    }

    fn call<T>(&mut self, f: &str, args: T) -> Result<(bool, u64, u64)>
    where
        T: Serialize,
    {
        tracing::trace!("performing a call to `{}`...", f);

        let args = serde_json::to_string(&args)?;
        tracing::trace!("args parsed as `{}`", args);

        let len = Value::I32(args.len() as i32);

        let ptr = self
            .instance
            .exports
            .get_function("malloc")?
            .call(&mut self.store, &[len.clone()])?
            .first()
            .ok_or(anyhow::anyhow!("malloc expected to return a pointer"))?
            .i32()
            .ok_or(anyhow::anyhow!(
                "malloc expected to return an i32 pointer"
            ))?;

        self.instance
            .exports
            .get_memory("memory")?
            .view(&self.store)
            .write(ptr as u64, args.as_bytes())?;

        let ptr = Value::I32(ptr);
        let result = self
            .instance
            .exports
            .get_function(f)?
            .call(&mut self.store, &[ptr, len])?
            .first()
            .ok_or(anyhow::anyhow!("function expected to return a value"))?
            .i64()
            .ok_or(anyhow::anyhow!("function expected to return an i64"))?;

        // wallet-core specifics
        let ptr = (result >> 32) as u64;
        let len = ((result << 32) >> 48) as u64;
        let success = ((result << 63) >> 63) == 0;

        tracing::trace!("call `{}` returned `{:?}`", f, (success, ptr, len));

        Ok((success, ptr, len))
    }

    fn take_bytes(
        &mut self,
        (success, ptr, len): (bool, u64, u64),
    ) -> Result<Vec<u8>> {
        tracing::trace!(
            "taking bytes from wallet-core of triplet `{:?}`",
            (success, ptr, len)
        );

        if !success {
            return Err(anyhow::anyhow!("call failed"));
        }

        let mut bytes = vec![0u8; len as usize];

        self.instance
            .exports
            .get_memory("memory")?
            .view(&self.store)
            .read(ptr, &mut bytes)?;

        self.instance.exports.get_function("free_mem")?.call(
            &mut self.store,
            &[Value::I32(ptr as i32), Value::I32(len as i32)],
        )?;

        tracing::trace!("bytes read and freed");

        Ok(bytes)
    }

    fn take_contents<T>(&mut self, response: (bool, u64, u64)) -> Result<T>
    where
        T: for<'d> Deserialize<'d>,
    {
        tracing::trace!(
            "taking contents from wallet-core from triplet `{:?}`",
            response
        );
        let bytes = self.take_bytes(response)?;

        let json = String::from_utf8(bytes)?;
        tracing::trace!("contents `{}` received; parsing...", json);

        let contents = serde_json::from_str(&json)?;
        tracing::trace!("contents parsed");

        Ok(contents)
    }
}

fn value_to_bytes(value: &Json) -> Result<Vec<u8>> {
    value
        .as_array()
        .ok_or(anyhow::anyhow!("array expected"))?
        .into_iter()
        .map(|v| {
            v.as_u64()
                .map(|v| v as u8)
                .ok_or(anyhow::anyhow!("unsigned integer expected"))
        })
        .collect::<Result<Vec<_>, _>>()
}
