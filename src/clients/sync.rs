// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::mem::size_of;

use dusk_wallet_core::Store;
use futures::StreamExt;
use phoenix_core::transaction::{ArchivedTreeLeaf, TreeLeaf};

use crate::{
    clients::Cache, rusk::RuskHttpClient, store::LocalStore, Address, Error,
    RuskRequest, MAX_ADDRESSES,
};

use super::TRANSFER_CONTRACT;

const RKYV_TREE_LEAF_SIZE: usize = size_of::<ArchivedTreeLeaf>();

pub(crate) async fn sync_db(
    client: &mut RuskHttpClient,
    store: &LocalStore,
    cache: &Cache,
    status: fn(&str),
    existing_addresses: &[Address],
) -> Result<usize, Error> {
    let addresses: Vec<_> = (0..MAX_ADDRESSES)
        .flat_map(|i| store.retrieve_ssk(i as u64))
        .map(|ssk| {
            let vk = ssk.view_key();
            let psk = vk.public_spend_key();
            (ssk, vk, psk)
        })
        .collect();

    status("Getting cached block height...");

    let mut last_height = cache.last_height()?;

    status("Fetching fresh notes...");

    let req = rkyv::to_bytes::<_, 8>(&last_height)
        .map_err(|_| Error::Rkyv)?
        .to_vec();

    let mut stream = client
        .call_raw(
            1,
            TRANSFER_CONTRACT,
            &RuskRequest::new("leaves_from_height", req),
            true,
        )
        .await?
        .bytes_stream();

    status("Connection established...");

    status("Streaming notes...");

    status(format!("From block: {}", last_height).as_str());

    // This buffer is needed because `.bytes_stream();` introduce additional
    // spliting of chunks according to it's own buffer
    let mut buffer = vec![];
    // This stores the number of addresses we need to create after a sync-up
    let mut addresses_to_create = 0;

    while let Some(http_chunk) = stream.next().await {
        buffer.extend_from_slice(&http_chunk?);

        let mut leaf_chunk = buffer.chunks_exact(RKYV_TREE_LEAF_SIZE);

        for leaf_bytes in leaf_chunk.by_ref() {
            let TreeLeaf { block_height, note } =
                rkyv::from_bytes(leaf_bytes).map_err(|_| Error::Rkyv)?;

            last_height = std::cmp::max(last_height, block_height);

            for (i, (ssk, vk, psk)) in addresses.iter().enumerate() {
                if vk.owns(&note) {
                    if existing_addresses.get(i).is_none() {
                        addresses_to_create = i;
                    }

                    let note_data = (note, note.gen_nullifier(ssk));
                    cache.insert(psk, block_height, note_data)?;

                    break;
                }
            }
        }

        buffer = leaf_chunk.remainder().to_vec();
    }

    println!("Last block: {}", last_height);

    cache.insert_last_height(last_height)?;

    Ok(addresses_to_create)
}
