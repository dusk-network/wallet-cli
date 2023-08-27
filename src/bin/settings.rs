// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::args::WalletArgs;

use std::fmt;

use tracing::Level;

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum LogFormat {
    Json,
    Plain,
    Coloured,
}

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum LogLevel {
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
pub struct Logging {
    /// Max log level
    pub level: LogLevel,
    /// Log format
    pub format: LogFormat,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Settings {
    pub logging: Logging,
    pub password: Option<String>,
}

pub struct SettingsBuilder {
    pub args: WalletArgs,
}

impl SettingsBuilder {
    pub fn build(self) -> Settings {
        let logging = Logging {
            level: self.args.log_level,
            format: self.args.log_type,
        };

        Settings {
            logging,
            password: self.args.password,
        }
    }
}

impl Settings {
    pub fn args(args: WalletArgs) -> SettingsBuilder {
        SettingsBuilder { args }
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

        writeln!(f, "{separator}")?;
        writeln!(f, "{}", self.logging)
    }
}
