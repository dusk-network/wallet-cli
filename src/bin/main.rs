// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

pub mod actions;
pub mod config;
pub mod prompt;
pub mod wallet;

use wallet_lib::error::Error;

use crate::actions::exec;

#[tokio::main]
async fn main() -> Result<(), Error> {
    if let Err(err) = exec().await {
        // display the error message (if any)
        println!("{}", err);
        // give cursor back to the user
        prompt::show_cursor()?;
    }
    Ok(())
}
