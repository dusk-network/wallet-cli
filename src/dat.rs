// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::DeserializableSlice;

use crate::crypto::decrypt;
use crate::store;
use crate::Error;

/// Binary prefix for old Dusk wallet files
pub const OLD_MAGIC: u32 = 0x1d0c15;
/// Binary prefix for new binary file format
pub const MAGIC: u32 = 0x72736b;

/// (Major, Minor, Patch, Pre, Pre-Higher)
type Version = (u8, u8, u8, u8, bool);

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum DatFileVersion {
    /// Legacy the oldest format
    Legacy,
    /// Preciding legacy, we have the old one
    OldWalletCli(Version),
    /// The newest one. All new saves are saved in this file format
    RuskBinaryFileFormat(Version),
}

pub(crate) fn get_seed_and_address(
    file: DatFileVersion,
    mut bytes: Vec<u8>,
    pwd: &[u8],
) -> Result<(store::Seed, u8), Error> {
    match file {
        DatFileVersion::Legacy => {
            if bytes[1] == 0 && bytes[2] == 0 {
                bytes.drain(..3);
            }

            bytes = decrypt(&bytes, pwd)?;

            // get our seed
            let seed = store::Seed::from_reader(&mut &bytes[..])
                .map_err(|_| Error::WalletFileCorrupted)?;

            Ok((seed, 1))
        }
        DatFileVersion::OldWalletCli((major, minor, _, _, _)) => {
            bytes.drain(..5);

            let result: Result<(store::Seed, u8), Error> = match (major, minor)
            {
                (1, 0) => {
                    let content = decrypt(&bytes, pwd)?;
                    let mut buff = &content[..];

                    let seed = store::Seed::from_reader(&mut buff)
                        .map_err(|_| Error::WalletFileCorrupted)?;

                    Ok((seed, 1))
                }
                (2, 0) => {
                    let content = decrypt(&bytes, pwd)?;
                    let mut buff = &content[..];

                    // extract seed
                    let seed = store::Seed::from_reader(&mut buff)
                        .map_err(|_| Error::WalletFileCorrupted)?;

                    // extract addresses count
                    Ok((seed, buff[0]))
                }
                _ => Err(Error::UnknownFileVersion(major, minor)),
            };

            result
        }
        DatFileVersion::RuskBinaryFileFormat(_) => {
            let rest = bytes.get(12..(12 + 96));
            if let Some(rest) = rest {
                let content = decrypt(rest, pwd)?;

                if let Some(seed_buff) = content.get(0..65) {
                    let seed = store::Seed::from_reader(&mut &seed_buff[0..64])
                        .map_err(|_| Error::WalletFileCorrupted)?;

                    let count = &seed_buff[64..65];

                    Ok((seed, count[0]))
                } else {
                    Err(Error::WalletFileCorrupted)
                }
            } else {
                Err(Error::WalletFileCorrupted)
            }
        }
    }
}

/// From the first 12 bytes of the file (header), we check version
///
/// https://github.com/dusk-network/rusk/wiki/Binary-File-Format/#header
pub(crate) fn check_version(
    bytes: Option<&[u8]>,
) -> Result<DatFileVersion, Error> {
    match bytes {
        Some(bytes) => {
            let header_bytes: [u8; 4] = bytes[0..4]
                .try_into()
                .map_err(|_| Error::WalletFileCorrupted)?;

            let magic = u32::from_le_bytes(header_bytes) & 0x00ffffff;

            if magic == OLD_MAGIC {
                // check for version information
                let (major, minor) = (bytes[3], bytes[4]);

                Ok(DatFileVersion::OldWalletCli((major, minor, 0, 0, false)))
            } else {
                let header_bytes = bytes[0..8]
                    .try_into()
                    .map_err(|_| Error::WalletFileCorrupted)?;

                let number = u64::from_be_bytes(header_bytes);

                let magic_num = (number & 0xFFFFFF00000000) >> 32;

                if (magic_num as u32) != MAGIC {
                    return Ok(DatFileVersion::Legacy);
                }

                let file_type = (number & 0x000000FFFF0000) >> 16;
                let reserved = number & 0x0000000000FFFF;

                if file_type != 0x200 {
                    return Err(Error::WalletFileCorrupted);
                };

                if reserved != 0x0 {
                    return Err(Error::WalletFileCorrupted);
                };

                let version_bytes = bytes[8..12]
                    .try_into()
                    .map_err(|_| Error::WalletFileCorrupted)?;

                let version = u32::from_be_bytes(version_bytes);

                let major = (version & 0xff000000) >> 24;
                let minor = (version & 0x00ff0000) >> 16;
                let patch = (version & 0x0000ff00) >> 8;
                let pre = (version & 0x000000f0) >> 4;
                let higher = version & 0x0000000f;

                let pre_higher = matches!(higher, 1);

                Ok(DatFileVersion::RuskBinaryFileFormat((
                    major as u8,
                    minor as u8,
                    patch as u8,
                    pre as u8,
                    pre_higher,
                )))
            }
        }
        None => Err(Error::WalletFileCorrupted),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distiction_between_versions() {
        // with magic number
        let old_wallet_file = vec![0x15, 0x0c, 0x1d, 0x02, 0x00];
        // no magic number just nonsense bytes
        let legacy_file = vec![
            0xab, 0x38, 0x81, 0x3b, 0xfc, 0x79, 0x11, 0xf9, 0x86, 0xd6, 0xd0,
        ];
        // new header
        let new_file = vec![
            0x00, 0x72, 0x73, 0x6b, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00,
        ];

        assert_eq!(
            check_version(Some(&old_wallet_file)).unwrap(),
            DatFileVersion::OldWalletCli((2, 0, 0, 0, false))
        );

        assert_eq!(
            check_version(Some(&legacy_file)).unwrap(),
            DatFileVersion::Legacy
        );

        assert_eq!(
            check_version(Some(&new_file)).unwrap(),
            DatFileVersion::RuskBinaryFileFormat((0, 0, 1, 0, false))
        );
    }
}
