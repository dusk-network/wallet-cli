// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::Error;
use serde::Serialize;

use wasmer::{imports, Instance, Module, Store as WasmStore, Value};

/// holds the wasm instance
pub struct WalletCore {
    pub store: WasmStore,
    pub instance: Instance,
}

impl WalletCore {
    pub fn new<B: AsRef<[u8]>>(bytes: B) -> anyhow::Result<Self> {
        let mut store = WasmStore::default();
        let module = Module::new(&store, bytes.as_ref())?;

        let import_object = imports! {};
        let instance = Instance::new(&mut store, &module, &import_object)?;

        Ok(Self { store, instance })
    }

    pub fn call<T>(&mut self, f: &str, args: T) -> anyhow::Result<Vec<u8>>
    where
        T: Serialize,
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

                return Ok(result_bytes);
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
