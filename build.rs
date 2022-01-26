// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("../schema/state.proto")?;
    Ok(())
}
