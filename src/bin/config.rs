// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use url::Url;

pub(crate) enum TransportMethod {
    Uds,
    Tcp,
    None,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct Transport {
    pub(crate) url: Option<Url>,
    pub(crate) path: Option<PathBuf>,
}

impl Transport {
    pub(crate) fn method(&self) -> TransportMethod {
        match (&self.url, &self.path) {
            (Some(_), Some(_)) => {
                if cfg!(windows) {
                    TransportMethod::Tcp
                } else {
                    TransportMethod::Uds
                }
            }
            (Some(_), None) => TransportMethod::Tcp,
            (None, Some(_)) => TransportMethod::Uds,
            (None, None) => TransportMethod::None,
        }
    }
}

impl From<&Transport> for String {
    fn from(transport: &Transport) -> String {
        let Transport { url, path } = transport;

        match (&url, &path) {
            (Some(_), Some(_)) => {
                if cfg!(windows) {
                    url.as_ref()
                        .map(|url| url.as_str().into())
                        .unwrap_or_default()
                } else {
                    path.as_ref()
                        .map(|path| path.to_string_lossy().into())
                        .unwrap_or_default()
                }
            }
            (Some(_), None) => url
                .as_ref()
                .map(|url| url.as_str().into())
                .unwrap_or_default(),
            (None, Some(_)) => path
                .as_ref()
                .map(|path| path.to_string_lossy().into())
                .unwrap_or_default(),

            (None, None) => String::from(""),
        }
    }
}

impl From<Transport> for String {
    fn from(transport: Transport) -> String {
        transport.into()
    }
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub(crate) struct Network {
    pub(crate) state: Transport,
    pub(crate) prover: Transport,
    pub(crate) explorer: Option<Url>,
    pub(crate) graphql: Url,
    pub(crate) network: Option<HashMap<String, Network>>,
}

use std::{fs, io};

/// Config holds the settings for the CLI wallet
#[derive(Debug)]
pub struct Config {
    /// Network configuration
    pub(crate) network: Network,
}

fn read_to_string<P: AsRef<Path>>(path: P) -> io::Result<Option<String>> {
    fs::read_to_string(&path)
        .map(Some)
        .or_else(|e| match e.kind() {
            io::ErrorKind::NotFound => Ok(None),
            _ => Err(e),
        })
}

impl Config {
    /// Attempt to load configuration from file
    pub fn load(profile: &Path) -> anyhow::Result<Config> {
        let profile = profile.join("config.toml");

        // PANIC: It's okay to stop execution here because we don't wanna
        // assume the config folder of the user
        let mut global_config = dirs::home_dir().expect("Cannot get home dir");

        global_config.push(".config");
        global_config.push(env!("CARGO_BIN_NAME"));
        global_config.push("config.toml");

        let contents = read_to_string(&profile)?
            .or(read_to_string(&global_config)?)
            .unwrap_or_else(|| {
                include_str!("../../default.config.toml").to_string()
            });

        let network: Network = toml::from_str(&contents)?;

        Ok(Config { network })
    }
}
