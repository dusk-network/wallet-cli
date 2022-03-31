// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::{path::Path, fs, io::ErrorKind};

use git2::Repository;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    compile_rusk_protos()?;
    Ok(())
}

/// Fetch and build latest protos from rusk-schema repository
fn compile_rusk_protos() -> Result<(), Box<dyn std::error::Error>> {

    let tmp_dir = Path::new("/tmp/rusk");

    // remove any temp source files
    remove_tmp_files(tmp_dir);

    // create temporary dir for proto files
    create_tmp_dir(tmp_dir);

    // clone schema files
    let _ = Repository::clone("https://github.com/dusk-network/rusk.git", tmp_dir)?;

    // build proto definitions
    let entrypoint = {
        let mut p = tmp_dir.to_path_buf();
        p.push("schema");
        p.push("state");
        p.with_extension("proto")
    };
    tonic_build::compile_protos(&entrypoint)?;

    Ok(())
}

fn create_tmp_dir(dir: &Path) {
    fs::create_dir_all(dir).expect(
        format!("Failed to create temporary dir: {}", dir.display())
            .as_str(),
    );
}

fn remove_tmp_files(dir: &Path) {
    // remove temp source files
    let rm = fs::remove_dir_all(dir);
    match rm {
        Ok(()) => (),
        Err(err) => match err.kind() {
            ErrorKind::NotFound => (),
            _ => panic!("Failed to remove {}. Please remove it yourself before next build.", dir.display()),
        }
    }
}
