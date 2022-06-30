use clap::{AppSettings, Parser, Subcommand};
use std::path::PathBuf;
pub use crate::dusk::{Dusk, Lux};

#[derive(Parser)]
#[clap(version)]
#[clap(name = "Dusk Wallet CLI")]
#[clap(author = "Dusk Network B.V.")]
#[clap(about = "A user-friendly, reliable command line interface to the Dusk wallet!", long_about = None)]
#[clap(global_setting(AppSettings::DeriveDisplayOrder))]
pub struct WalletArgs {
    /// Directory to store user data [default: `$HOME/.dusk`]
    #[clap(short, long)]
    pub data_dir: Option<PathBuf>,

    /// Name for your wallet [default: `$(whoami)`]
    #[clap(short = 'n', long, value_name = "NAME")]
    pub wallet_name: Option<String>,

    /// Path to a wallet file. Overrides `data-dir` and `wallet-name`, useful
    /// when loading a wallet that's not in the default directory.
    #[clap(short = 'f', long, parse(from_os_str), value_name = "PATH")]
    pub wallet_file: Option<PathBuf>,

    /// IPC method for communication with rusk [uds, tcp_ip]
    #[clap(short = 'i', long)]
    pub ipc_method: Option<String>,

    /// Rusk address: socket path or fully quallified URL
    #[clap(short = 'r', long)]
    pub rusk_addr: Option<String>,

    /// Prover service address
    #[clap(short = 'p', long)]
    pub prover_addr: Option<String>,

    /// Skip wallet recovery phrase (useful for headless wallet creation)
    #[clap(long)]
    pub skip_recovery: Option<bool>,

    /// Wait for transaction confirmation from network
    #[clap(long)]
    pub wait_for_tx: Option<bool>,

    /// Command
    #[clap(subcommand)]
    pub command: Option<CliCommand>,
}

#[derive(Clone, Subcommand)]
pub enum CliCommand {
    /// Create a new wallet
    Create,

    /// Restore a lost wallet
    Restore,

    /// Check your current balance
    Balance {
        /// Key index
        #[clap(short, long, default_value_t = 0)]
        key: u64,

        /// Check maximum spendable balance
        #[clap(long)]
        spendable: bool,
    },

    /// Retrieve public spend key
    Address {
        /// Key index
        #[clap(short, long, default_value_t = 0)]
        key: u64,
    },

    /// Send DUSK through the network
    Transfer {
        /// Key index from which to send DUSK
        #[clap(short, long, default_value_t = 0)]
        key: u64,

        /// Receiver address
        #[clap(short, long)]
        rcvr: String,

        /// Amount of DUSK to send
        #[clap(short, long)]
        amt: Dusk,

        /// Max amt of gas for this transaction
        #[clap(short = 'l', long)]
        gas_limit: Option<u64>,

        /// Max price you're willing to pay for gas used (in LUX)
        #[clap(short = 'p', long)]
        gas_price: Option<Lux>,
    },

    /// Start staking DUSK
    Stake {
        /// Key index from which to stake DUSK
        #[clap(short, long, default_value_t = 0)]
        key: u64,

        /// Staking key to sign this stake
        #[clap(short, long, default_value_t = 0)]
        stake_key: u64,

        /// Amount of DUSK to stake
        #[clap(short, long)]
        amt: Dusk,

        /// Max amt of gas for this transaction
        #[clap(short = 'l', long)]
        gas_limit: Option<u64>,

        /// Max price you're willing to pay for gas used (in LUX)
        #[clap(short = 'p', long)]
        gas_price: Option<Lux>,
    },

    /// Check your stake information
    StakeInfo {
        /// Staking key used to sign the stake
        #[clap(short, long, default_value_t = 0)]
        key: u64,

        /// Check accumulated reward
        #[clap(long)]
        reward: bool,
    },

    /// Unstake a key's stake
    Unstake {
        /// Key index from which your DUSK was staked
        #[clap(short, long, default_value_t = 0)]
        key: u64,

        /// Staking key index used for this stake
        #[clap(short, long, default_value_t = 0)]
        stake_key: u64,

        /// Max amt of gas for this transaction
        #[clap(short = 'l', long)]
        gas_limit: Option<u64>,

        /// Max price you're willing to pay for gas used (in LUX)
        #[clap(short = 'p', long)]
        gas_price: Option<Lux>,
    },

    /// Withdraw accumulated reward for a stake key
    Withdraw {
        /// Key index to pay transaction costs
        #[clap(short, long, default_value_t = 0)]
        key: u64,

        /// Stake key index with the accumulated reward
        #[clap(short, long, default_value_t = 0)]
        stake_key: u64,

        /// Address to which the reward will be sent to
        #[clap(short, long)]
        refund_addr: String,

        /// Max amt of gas for this transaction
        #[clap(short = 'l', long)]
        gas_limit: Option<u64>,

        /// Max price you're willing to pay for gas used (in LUX)
        #[clap(short = 'p', long)]
        gas_price: Option<Lux>,
    },

    /// Export BLS provisioner key pair
    Export {
        /// Key index from which your DUSK was staked
        #[clap(short, long, default_value_t = 0)]
        key: u64,

        /// Don't encrypt the output file
        #[clap(long)]
        plaintext: bool,
    },

    /// Run in interactive mode (default)
    Interactive,
}

impl CliCommand {
    pub fn uses_wallet(&self) -> bool {
        !matches!(*self, Self::Create | Self::Restore | Self::Interactive)
    }
}