use std::mem::size_of;
use std::sync::Arc;

use dusk_wallet_core::Store;
use flume::Sender;
use futures::StreamExt;
use phoenix_core::transaction::{ArchivedTreeLeaf, TreeLeaf};

use crate::{
    clients::Cache, rusk::RuskHttpClient, store::LocalStore, Error,
    RuskRequest, MAX_ADDRESSES,
};

use super::TRANSFER_CONTRACT;

const RKYV_TREE_LEAF_SIZE: usize = size_of::<ArchivedTreeLeaf>();
pub const SYNC_INTERVAL_SECONDS: u64 = 3;

pub(crate) async fn sync_db(
    client: &mut RuskHttpClient,
    store: &LocalStore,
    cache: &Cache,
    status: fn(&str),
    sender: Arc<Sender<String>>,
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
    let _ = sender.send("Fetching notes from network".to_string());

    // This buffer is needed because `.bytes_stream();` introduce additional
    // spliting of chunks according to it's own buffer
    let mut buffer = vec![];

    while let Some(chunk) = stream.next().await {
        buffer.extend_from_slice(&chunk?);
        if buffer.len() < RKYV_TREE_LEAF_SIZE {
            continue;
        }
        let TreeLeaf { block_height, note } =
            rkyv::from_bytes(&buffer).map_err(|_| Error::Rkyv)?;
        let txn = cache.txn();

        buffer.clear();

        last_height = std::cmp::max(last_height, block_height);

        for (ssk, vk, psk) in addresses.iter() {
            if vk.owns(&note) {
                cache.insert(
                    psk,
                    block_height,
                    (note, note.gen_nullifier(ssk)),
                    txn,
                )?;

                break;
            }
        }
    }

    println!("Last block: {}", last_height);

    cache.insert_last_height(last_height)?;
    let _ = sender.send("Finished fetching notes from network".to_string());

    Ok(())
}
