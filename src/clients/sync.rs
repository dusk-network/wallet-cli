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
    clients::Cache, rusk::RuskHttpClient, store::LocalStore, Error,
    RuskRequest, MAX_ADDRESSES,
};

use super::TRANSFER_CONTRACT;

const RKYV_TREE_LEAF_SIZE: usize = size_of::<ArchivedTreeLeaf>();

pub(crate) async fn sync_db(
    client: &mut RuskHttpClient,
    store: &LocalStore,
    cache: &Cache,
    status: fn(&str),
) -> Result<(), Error> {
    let addresses: Vec<_> = (0..MAX_ADDRESSES)
        .flat_map(|i| store.retrieve_ssk(i as u64))
        .map(|ssk| {
            let vk = ssk.view_key();
            let psk = vk.public_spend_key();
            (ssk, vk, psk)
        })
        .collect();

    status("Getting cached block height...");

    let mut last_pos = cache.last_pos()?;

    status("Fetching fresh notes...");

    let req = rkyv::to_bytes::<_, 8>(&(last_pos + 1))
        .map_err(|_| Error::Rkyv)?
        .to_vec();

    let mut stream = client
        .call_raw(
            1,
            TRANSFER_CONTRACT,
            &RuskRequest::new("leaves_from_pos", req),
            true,
        )
        .await?
        .bytes_stream();

    status("Connection established...");

    status("Streaming notes...");

    // This buffer is needed because `.bytes_stream();` introduce additional
    // spliting of chunks according to it's own buffer
    let mut buffer = vec![];

    while let Some(http_chunk) = stream.next().await {
        buffer.extend_from_slice(&http_chunk?);

        let mut leaf_chunk = buffer.chunks_exact(RKYV_TREE_LEAF_SIZE);

        for leaf_bytes in leaf_chunk.by_ref() {
            let TreeLeaf { block_height, note } = rkyv::from_bytes(leaf_bytes)
                .map_err(|_| Error::Rkyv)
                .map_err(|e| {
                    println!("Invalid note {}", hex::encode(leaf_bytes));
                    e
                })?;
            if *note.pos()==0 {
                println!("Buffer: {}", hex::encode(leaf_bytes));
                println!("Note: {note:#?}");
            }

            last_pos = std::cmp::max(last_pos, *note.pos());

            for (ssk, vk, psk) in addresses.iter() {
                if vk.owns(&note) {
                    let note_data = (note, note.gen_nullifier(ssk));
                    cache.insert(psk, block_height, note_data)?;

                    break;
                }
            }
            cache.insert_last_pos(last_pos)?;
        }

        buffer = leaf_chunk.remainder().to_vec();
    }

    cache.insert_last_pos(last_pos)?;

    Ok(())
}
