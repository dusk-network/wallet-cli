use std::path::PathBuf;

use super::rusk::RuskStateClient;

use crate::cache::Cache;
use crate::store::LocalStore;
use crate::{Error, MAX_ADDRESSES};

use dusk_bytes::DeserializableSlice;
use dusk_wallet_core::Store;
use futures::StreamExt;
use phoenix_core::Note;
use rusk_schema::GetNotesRequest;

/// The method to use when sync-ing with the network
#[derive(clap::ValueEnum, Debug, Clone)]
pub enum SyncMode {
    /// Sync quietly and periodically in the background while the wallet
    /// is running. This should be the default value
    Periodic,
    /// Sync everytime an addresses is selected.
    OnAddressRequest,
}

/// Sync the cache with notes from the network
pub async fn sync_up(
    mut client: RuskStateClient,
    cache_dir: &PathBuf,
    store: LocalStore,
    status: fn(&str),
) -> Result<(), Error> {
    let mut cache = Cache::new(cache_dir, &store)?;

    status("Starting Sync...");
    status("Getting cached block height...");

    let mut last_height = cache.last_height()?;

    let addresses: Vec<_> = (0..MAX_ADDRESSES)
        .flat_map(|i| store.retrieve_ssk(i as u64))
        .map(|ssk| {
            let vk = ssk.view_key();
            let psk = vk.public_spend_key();
            (ssk, vk, psk)
        })
        .collect();

    let msg = GetNotesRequest {
        height: last_height,
        vk: vec![],
    };

    let req = tonic::Request::new(msg);
    let mut stream = client.get_notes(req).await?.into_inner();

    status("Connection established...");
    status("Syncing notes...");
    status(format!("From block: {}", last_height).as_str());

    while let Some(item) = stream.next().await {
        let rsp = item?;

        last_height = std::cmp::max(last_height, rsp.height);

        let note = Note::from_slice(&rsp.note)?;

        for (ssk, vk, psk) in addresses.iter() {
            if vk.owns(&note) {
                cache.insert(
                    psk,
                    rsp.height,
                    (note, note.gen_nullifier(ssk)),
                )?;

                break;
            }
        }
    }

    status("Synced Notes");

    println!("Last block: {}", last_height);

    status("Persisting notes...");

    cache.persist(last_height)?;

    Ok(())
}

impl Default for SyncMode {
    fn default() -> Self {
        Self::Periodic
    }
}
