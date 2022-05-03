// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[macro_export]
macro_rules! status {
    ($status: literal) => {
        tracing::event!(
            target:"status",
            tracing::Level::INFO,
            msg=$status
        );
    };
    ($status: expr) => {
        tracing::event!(
            target:"status",
            tracing::Level::INFO,
            msg=$status.as_str()
        );
    };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {{
        tracing::event!(
            target:"info",
            tracing::Level::INFO,
            $($arg)*
        );
    }};
}

#[macro_export]
macro_rules! output {
    ($output: expr) => {{
        let msg = format!("{}", $output);
        tracing::event!(
            target:"output",
            tracing::Level::INFO,
            msg=msg.as_str(),
        );
    }};
}

pub use {info, output, status};

use super::prompt;
use tracing::Level;
use tracing_subscriber::Layer;

pub struct Logger {
    interactive: bool,
    level: Level,
}

impl Logger {
    /// Create a new global logger
    pub fn new(level: &str, interactive: bool) -> Logger {
        let level = match level {
            "error" => tracing::Level::ERROR,
            "warn" => tracing::Level::WARN,
            "info" => tracing::Level::INFO,
            "debug" => tracing::Level::DEBUG,
            "trace" => tracing::Level::TRACE,
            _ => unreachable!(),
        };
        Logger { interactive, level }
    }
}

impl<S> Layer<S> for Logger
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        // filter by log level
        let level = *event.metadata().level();
        match level {
            Level::TRACE => return,
            Level::DEBUG => return,
            _ => (),
        }

        // read event content
        let mut evt = EventMessage::new("");
        event.record(&mut evt);

        // classify event type
        let evt_msg = match event.metadata().target() {
            "info" => LogMessage::Info(evt.msg),
            "status" => LogMessage::Status(evt.msg),
            "output" => LogMessage::Output(evt.msg),
            _ => LogMessage::Empty,
        };

        //println!("{} {:?}", self.interactive, evt_msg);

        // do whatever we gotta do with it
        if self.interactive {
            match evt_msg {
                LogMessage::Status(msg) => {
                    prompt::status(msg.as_str());
                }
                LogMessage::Info(msg) => println!("\r{}", msg),
                LogMessage::Output(msg) => println!("\r{}", msg),
                _ => (),
            }
        } else if let LogMessage::Output(msg) = evt_msg {
            println!("\r{}", msg);
        }
    }
}

#[derive(Debug)]
enum LogMessage {
    Status(String),
    Info(String),
    Output(String),
    Empty,
}

struct EventMessage {
    msg: String,
}

impl EventMessage {
    pub fn new<S>(msg: S) -> Self
    where
        S: Into<String>,
    {
        EventMessage { msg: msg.into() }
    }
}

impl tracing::field::Visit for EventMessage {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "msg" {
            self.msg = value.to_string();
        }
    }

    fn record_debug(
        &mut self,
        _field: &tracing::field::Field,
        value: &dyn std::fmt::Debug,
    ) {
        println!("\r{:?}", value); // TODO: Needs work
    }
}
