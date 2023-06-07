use crate::temp_config::Config;
use dusk_wallet::TransportTCP;
use tokio::runtime::Handle;

use blake3::Hash;
use criterion::*;
use dusk_wallet::{SecureWalletFile, Wallet, WalletPath};
use dusk_wallet_core::{StateClient, Store};
use phoenix_core::Note;

mod temp_config;

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub(crate) struct WalletFile {
    path: WalletPath,
    pwd: Hash,
}

impl SecureWalletFile for WalletFile {
    fn path(&self) -> &WalletPath {
        &self.path
    }

    fn pwd(&self) -> Hash {
        self.pwd
    }
}

async fn setup_wallet() -> Wallet<WalletFile> {
    let profile_folder = PathBuf::from("/Users/Work/.dusk/rusk-wallet");
    let mut wallet_folder = profile_folder.clone();

    wallet_folder.push("wallet.dat");

    let cfg = Config::load(&profile_folder).unwrap();

    let path = WalletPath::new(&wallet_folder);
    let pwd = "pilot";
    let hash = blake3::hash(pwd.as_bytes());

    let file = WalletFile { path, pwd: hash };

    let mut wallet = Wallet::from_file(file).unwrap();

    wallet
        .connect_with_status(
            TransportTCP::new(&cfg.network.state, &cfg.network.prover),
            |_| {},
        )
        .await
        .expect("cannot connect to wallet");

    wallet
}

fn fetch_notes(wallet: &Wallet<WalletFile>) -> Vec<(Note, u64)> {
    if let Some(wallet) = &wallet.wallet {
        let ssk_index = 1_u64;
        let ssk = wallet.store().retrieve_ssk(ssk_index).unwrap();
        let vk = ssk.view_key();

        let notes = wallet.state().fetch_notes(&vk).unwrap();

        notes
    } else {
        Vec::new()
    }
}

#[tokio::main]
async fn criterion_benchmark(c: &mut Criterion) {
    let wallet = setup_wallet().await;

    let mut group = c.benchmark_group("sample-size-example");
    group.significance_level(0.01).sample_size(10);

    group.bench_function("fetch notes 1", |b| b.iter(|| fetch_notes(&wallet)));

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
