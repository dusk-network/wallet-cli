use std::sync::Arc;

use dusk_bytes::DeserializableSlice;
use dusk_wallet_core::Store;
use flume::Sender;
use futures::StreamExt;
use phoenix_core::Note;
use rusk_schema::GetNotesRequest;

use crate::{
    clients::Cache, rusk::RuskStateClient, store::LocalStore, Error,
    MAX_ADDRESSES,
};

pub const SYNC_INTERVAL_SECONDS: u64 = 3;

pub(crate) async fn sync_db(
    client: &mut RuskStateClient,
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
    let msg = GetNotesRequest {
        height: last_height,
        vk: vec![], // empty vector means *all* notes will be streamed
    };
    let req = tonic::Request::new(msg);
    let mut stream = client.get_notes(req).await?.into_inner();
    status("Connection established...");

    status("Streaming notes...");

    status(format!("From block: {}", last_height).as_str());
    let _ = sender.send("Fetching notes from network".to_string());

    while let Some(item) = stream.next().await {
        let rsp = item?;
        let note = Note::from_slice(&rsp.note)?;
        let txn = cache.txn();

        last_height = std::cmp::max(last_height, rsp.height);

        for (ssk, vk, psk) in addresses.iter() {
            if vk.owns(&note) {
                cache.insert(
                    psk,
                    rsp.height,
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
