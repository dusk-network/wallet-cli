// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::config::{Network, Transport};
use crate::io::WalletArgs;

use std::fmt;
use std::path::PathBuf;
use tracing::Level;
use url::Url;

#[derive(clap::ValueEnum, Debug, Clone)]
pub(crate) enum LogFormat {
    Json,
    Plain,
    Coloured,
}

#[derive(clap::ValueEnum, Debug, Clone)]
pub(crate) enum LogLevel {
    /// Designates very low priority, often extremely verbose, information.
    Trace,
    /// Designates lower priority information.
    Debug,
    /// Designates useful information.
    Info,
    /// Designates hazardous situations.
    Warn,
    /// Designates very serious errors.
    Error,
}

#[derive(Debug)]
pub(crate) struct Logging {
    /// Max log level
    pub level: LogLevel,
    /// Log format
    pub format: LogFormat,
}
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct Settings {
    pub(crate) state: Transport,
    pub(crate) prover: Transport,
    pub(crate) explorer: Option<Url>,
    pub(crate) graphql: Url,

    pub(crate) logging: Logging,

    pub(crate) profile: PathBuf,
    pub(crate) password: Option<String>,
}

pub(crate) struct SettingsBuilder {
    profile: PathBuf,
    pub(crate) args: WalletArgs,
}

impl SettingsBuilder {
    pub fn profile(&self) -> &PathBuf {
        &self.profile
    }

    pub fn network(self, network: Network) -> Settings {
        let args = self.args;

        let network = match (args.network, network.clone().network) {
            (Some(label), Some(mut networks)) => networks.remove(&label),
            (_, _) => None,
        }
        .unwrap_or(network);

        let url = args.state.as_ref().and_then(|value| Url::parse(value).ok());
        let path = url
            .as_ref()
            .map_or(args.state.as_ref().map(PathBuf::from), |_| None);

        let state = if url.is_some() || path.is_some() {
            Transport { url, path }
        } else {
            network.state
        };

        let url = args
            .prover
            .as_ref()
            .and_then(|value| Url::parse(value).ok());

        let path = url
            .as_ref()
            .map_or(args.prover.as_ref().map(PathBuf::from), |_| None);

        let prover = if url.is_some() || path.is_some() {
            Transport { url, path }
        } else {
            network.prover
        };

        let explorer = network.explorer;
        let graphql = network.graphql;

        let profile = args.profile.as_ref().cloned().unwrap_or(self.profile);

        let password = args.password;

        let logging = Logging {
            level: args.log_level,
            format: args.log_type,
        };

        Settings {
            state,
            prover,
            explorer,
            graphql,
            logging,
            profile,
            password,
        }
    }
}

impl Settings {
    pub fn args(args: WalletArgs) -> SettingsBuilder {
        let profile = if let Some(path) = &args.profile {
            path.clone()
        } else {
            let mut path = dirs::home_dir().expect("OS not supported");
            path.push(".dusk");
            path.push(env!("CARGO_BIN_NAME"));
            path
        };

        SettingsBuilder { profile, args }
    }
}

impl From<&LogLevel> for Level {
    fn from(level: &LogLevel) -> Level {
        match level {
            LogLevel::Trace => Level::TRACE,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Info => Level::INFO,
            LogLevel::Warn => Level::WARN,
            LogLevel::Error => Level::ERROR,
        }
    }
}

impl fmt::Display for LogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Json => "json",
                Self::Plain => "plain",
                Self::Coloured => "coloured",
            }
        )
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Trace => "trace",
                Self::Debug => "debug",
                Self::Info => "info",
                Self::Warn => "warn",
                Self::Error => "error",
            }
        )
    }
}

impl fmt::Display for Logging {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Logging: [{}] ({})", self.level, self.format)
    }
}

impl fmt::Display for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let separator = "─".repeat(14);
        writeln!(f, "{separator}")?;
        writeln!(f, "Settings")?;
        writeln!(f, "{separator}")?;
        writeln!(f, "Profile: {}", self.profile.display())?;
        writeln!(
            f,
            "Password: {}",
            if self.password.is_some() {
                "[Set]"
            } else {
                "[Not set]"
            }
        )?;
        writeln!(f, "{}", separator)?;
        writeln!(f, "state: {}", String::from(&self.state))?;
        writeln!(f, "prover: {}", String::from(&self.prover))?;

        if let Some(explorer) = &self.explorer {
            writeln!(f, "explorer: {explorer}")?;
        }

        writeln!(f, "GraphQL: {}", self.graphql)?;
        writeln!(f, "{separator}")?;
        writeln!(f, "{}", self.logging)
    }
}
