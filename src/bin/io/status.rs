// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::io::{stdout, Write};
use std::thread;
use std::time::Duration;

use tracing::info;

const STATUS_SIZE: usize = 250;

/// Prints an interactive status message
pub(crate) fn interactive(status: &str) {
    println!("{}", status.len());
    let filln = STATUS_SIZE - status.len();
    let fill = if filln > 0 {
        " ".repeat(filln)
    } else {
        "".to_string()
    };
    print!("{}{}\r", status, fill);
    let mut stdout = stdout();
    stdout.flush().unwrap();
    thread::sleep(Duration::from_millis(85));
}

/// Logs the status message at info level
pub(crate) fn headless(status: &str) {
    info!(status);
}
