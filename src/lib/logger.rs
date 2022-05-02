// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use tracing_subscriber::Layer;
use tracing::Level;

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
        Logger{interactive, level}

    }

}

impl<S> Layer<S> for Logger where S: tracing::Subscriber {
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

        println!("Got event! {}", self.interactive);
        println!("  level={:?}", event.metadata().level());
        println!("  target={:?}", event.metadata().target());
        println!("  name={:?}", event.metadata().name());
        for field in event.fields() {
            println!("  field={}", field.name());
        }
    }
}
