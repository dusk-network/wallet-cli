# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `default.config.toml` for the default configuration settings [#57]
- Add `settings` subcommand to show the current settings [#57]
- Add `--password` as global argument [#57]
- Add `--skip-recovery` to `create` subcommand [#57]
- Add `--file` to `restore` subcommand [#57]
- Add `Settings` type to merge `Config` (from toml) and `WalletArgs` (from CLI) [#57]
- Add `address` module
- Add `gas` module
- Add `settings` module [#57]
- Add `is_enough` method to `Gas`
- Add `Create`, `Restore` and `Settings` for both `Command` and `RunResult` enums [#72]
- Add `LogFormat` and `LogLevel` enums to enforce the set of value from args [#57]
- Add `From block` and `Last block` during fetching
- Add missing documentations
- Add `Seed` type in `store` module

### Changed

- Change program behavior to quit if wrong seed phrase is given [#49] 
- Change program behavior to have three attempts for entering a password [#46]
- Change error handling to use the `anyhow` crate in `bin`[#87]
- Change error handling to use the `thiserror` crate in `lib`[#87]
- Change `config.toml` format [#57]
- Change from multiple wallets to one wallet for a single profile dir [#72]
- Rename `dusk` module to `currency` module
- Rename `address` subcommand to `addresses`
- Change `set_price` and `set_limit` for `Gas` to works with `Option`
- Change part of the functions to either receive the `password` or the `settings` [#57]
- Move `config` module outside `io` [#57]
- Change few UI strings
- Update rust-toolchain from `nightly-2022-02-19` to `nightly-2022-08-28`

### Removed

- Rename `--data-dir` argument option to `--profile` [#57]
- Remove `--wallet-name` argument option [#72]
- Remove `--network` argument option to chose the network to connect with [#57]
- Remove `interactive` subcommand [#57]
- Remove `--skip-recovery` as global argument [#57]
- Remove `--wait-for-tx` (now all the transaction wait by default) [#57]
- Remove `merge` method from `Config` in favour of `Settings` type [#57]
- Remove `Command::NotSupported` [#57]
- Rename `DEFAULT_GAS_LIMIT`, `DEFAULT_GAS_PRICE`, `MIN_GAS_LIMIT`
- Remove `Addresses` type in favour of `Vec<Address>`
- Remove `refund-addr` arg in `withdraw` command [#86]

### Fixed

- Fix wrong condition involved `gas.is_enough()`[#91]
- Fix `balance` subcommand: it didn't work because the address given wasn't claimed
- Fix BLS keys exported with wrong extensions [#84]

## [0.11.1] - 2022-08-24

### Added

- Add prompt confirm_recovery_phrase to display the recovery phrase [#70]
- Add Windows terminal compatibility [#68]

### Changed

- Change `LoggingConfig` to be optional [#73]
- Replace `error!` macro with `eprintln!` macro [#73]
- Change `Return` to `Back` in the menu

## [0.11.0] - 2022-08-17

### Added

- New public `Wallet` struct exposing all wallet operations as library [#54]
- New `Address` type to identify and work with addresses [#54]
- Logging capabilities with customizable `log_level` and `log_type` [#11]

### Changed

- Project is now a public facing library [#54]
- Our reference implementation is included under `src/bin` [#54]
- UX flow is now address-based to match that of the web wallet [#59]
- Anything that's not strictly program output is redirected to stderr [#11]

## [0.10.0] - 2022-07-06

### Added

- Add `src/bin` to gather the module related to the I/O ops [#51]
- Add `autobins` to Cargo.toml to prevent bins auto discovery [#51]
- Add `[lib]` and `[[bin]]` sections to Cargo.toml to decouple bin and lib [#51]
- Add `src/bin/io` to gather all modules related to I/O [#51]
- Add `status` mod as temp workaround to make the lib compile [#51]
- Add `actions` mod with all the actions previously in `main` [#51]

### Changed

- Rename `src/mod.rs` to `src/lib.rs` to be compliant with 2018 edition [#51]
- Refactor `main` to be more readable [#51]
- Update imports in the code to reflect the new files structure [#51]

## [0.9.0] - 2022-05-25

### Added

- Flag `--spendable` to `Balance` command [#40]
- Flag `--reward` to `StakeInfo` command [#40]

### Changed

- Commands run in headless mode do not provide dynamic status updates [#40]

## [0.8.0] - 2022-05-04

### Added

- Block trait for easier blocking on futures [#32]
- Withdraw reward command [#26]

### Changed

- Upgraded cache implementation to use `microkelvin` instead of `rusqlite` [#32]
- Use streaming `GetNotes` call instead of `GetNotesOwnedBy` [#32]
- Enhance address validity checks on interactive mode [#28]
- Prevent exit on prepare command errors [#27]
- Adapt balance to the new State [#24]
- Rename `withdraw-stake` to `unstake` [#26]
- Introduce Dusk type for currency management [#4]

### Fixed

- Fix cache bug preventing adding all notes to it [#35]
- Fix address validation by parsing address first [#35]

## [0.7.0] - 2022-04-13

### Added

- Notes cache [#650]
- Settings can be loaded from a config file [#637]
- Create config file if not exists [#647]
- Notify user when defaulting configuration [#655]
- Implementation for `State`'s `fetch_block_height` [#651]
- Option to wait for transaction confirmation [#680]
- Default to TCP/IP on Windows [#6]

### Changed

- Export consensus public key as binary
- Interactive mode allows for directory and wallet file overriding [#630]
- Client errors implemented, Rusk error messages displayed without metadata [#629]
- Transactions from wallets with no balance are halted immediately [#631]
- Rusk and prover connections decoupled [#659]
- Use upper-case DUSK for units of measure [#672]
- Use DUSK as unit for stake and transfer [#668]

### Fixed

- `data_dir` can be properly overriden [#656]
- Invalid configuration should not fallback into default [#670]
- Prevent interactive process from quitting on wallet execution errors [#18]

## [0.5.2] - 2022-03-01

### Added

- Optional configuration item to specify the prover URL [#612]
- Get Stake information subcommand [#619]

## [0.5.1] - 2022-02-26

### Added

- Display progress info about transaction preparation [#600]
- Display confirmation before sending a transaction [#602]

### Changed

- Use hex-encoded tx hashes on user-facing messages [#597]
- Open or display explorer URL on succesful transactions [#598]

## [0.5.0] - 2022-02-26

### Changed

- Update `canonical` across the entire Rusk stack [#606]

## [0.4.0] - 2022-02-17

### Changed

- Use the Dusk denomination from `rusk-abi` [#582]

## [0.3.1] - 2022-02-17

### Changed

- Default to current wallet directory for exported keys [#574]
- Add an additional plain text file with the base58-encoded public key [#574]

## [0.3.0] - 2022-02-17

### Removed

- Stake expiration [#566]

## [0.2.4] - 2022-02-15

### Added

- Allow for headless wallet creation [#569]

### Changed

- TX output in wallet instead of within client impl

## [0.2.3] - 2022-02-10

### Added

- Pretty print wallet-core errors [#554]

## [0.2.2] - 2022-02-10

### Changed

- Interactive mode prevents sending txs with insufficient balance [#547]

### Fixed

- Panic when UDS socket is not available

## [0.2.1] - 2022-02-09

### Changed

- Default `gas_price` from 0 to 0.001 Dusk [#539]

## [0.2.0] - 2022-02-04

### Added

- Wallet file encoding version [#524]

### Changed

- Default to UDS transport [#520]

## [0.1.3] - 2022-02-01

### Added

- Offline mode [#499] [#507]
- Live validation to user interactive input
- Improved navigation through interactive menus
- "Pause" after command outputs for better readability

### Fixed

- Bad UX when creating an already existing wallet with default name

## [0.1.2] - 2022-01-31

### Added

- Enable headless mode [#495]
- Introduce interactive mode by default [#492]
- Add Export command for BLS PubKeys [#505]

## [0.1.1] - 2022-01-27

### Added

- Wallet file encryption using AES [#482]

### Changed

- Common `Error` struct for this crate [#479]
- Password hashing using blake3

### Removed

- Recovery password

## [0.1.0] - 2022-01-25

### Added

- `rusk-wallet` crate to workspace
- Argument and command parsing, with help output
- Interactive prompts for authentication
- BIP39 mnemonic support for recovery phrase
- Implementation of `Store` trait from `wallet-core`
- Implementation of `State` and `Prover` traits from `wallet-core`

[#49]: https://github.com/dusk-network/wallet-cli/issues/49
[#46]: https://github.com/dusk-network/wallet-cli/issues/46
[#87]: https://github.com/dusk-network/wallet-cli/issues/87
[#86]: https://github.com/dusk-network/wallet-cli/issues/86
[#84]: https://github.com/dusk-network/wallet-cli/issues/84
[#72]: https://github.com/dusk-network/wallet-cli/issues/72
[#57]: https://github.com/dusk-network/wallet-cli/issues/57
[#70]: https://github.com/dusk-network/wallet-cli/issues/70
[#73]: https://github.com/dusk-network/wallet-cli/issues/73
[#68]: https://github.com/dusk-network/wallet-cli/issues/68
[#11]: https://github.com/dusk-network/wallet-cli/issues/11
[#59]: https://github.com/dusk-network/wallet-cli/issues/59
[#54]: https://github.com/dusk-network/wallet-cli/issues/54
[#51]: https://github.com/dusk-network/wallet-cli/issues/51
[#40]: https://github.com/dusk-network/wallet-cli/issues/40
[#35]: https://github.com/dusk-network/wallet-cli/issues/35
[#32]: https://github.com/dusk-network/wallet-cli/issues/32
[#28]: https://github.com/dusk-network/wallet-cli/issues/28
[#27]: https://github.com/dusk-network/wallet-cli/issues/27
[#26]: https://github.com/dusk-network/wallet-cli/issues/26
[#24]: https://github.com/dusk-network/wallet-cli/issues/24
[#18]: https://github.com/dusk-network/wallet-cli/issues/18
[#6]: https://github.com/dusk-network/wallet-cli/issues/6
[#4]: https://github.com/dusk-network/wallet-cli/issues/4
[#680]: https://github.com/dusk-network/rusk/issues/680
[#672]: https://github.com/dusk-network/rusk/issues/672
[#670]: https://github.com/dusk-network/rusk/issues/670
[#668]: https://github.com/dusk-network/rusk/issues/668
[#659]: https://github.com/dusk-network/rusk/issues/659
[#656]: https://github.com/dusk-network/rusk/issues/656
[#655]: https://github.com/dusk-network/rusk/issues/655
[#651]: https://github.com/dusk-network/rusk/issues/651
[#650]: https://github.com/dusk-network/rusk/issues/650
[#647]: https://github.com/dusk-network/rusk/issues/647
[#637]: https://github.com/dusk-network/rusk/issues/637
[#631]: https://github.com/dusk-network/rusk/issues/631
[#630]: https://github.com/dusk-network/rusk/issues/630
[#629]: https://github.com/dusk-network/rusk/issues/629
[#619]: https://github.com/dusk-network/rusk/issues/619
[#612]: https://github.com/dusk-network/rusk/issues/612
[#606]: https://github.com/dusk-network/rusk/issues/606
[#602]: https://github.com/dusk-network/rusk/issues/602
[#600]: https://github.com/dusk-network/rusk/issues/600
[#598]: https://github.com/dusk-network/rusk/issues/598
[#597]: https://github.com/dusk-network/rusk/issues/597
[#582]: https://github.com/dusk-network/rusk/issues/582
[#574]: https://github.com/dusk-network/rusk/issues/574
[#569]: https://github.com/dusk-network/rusk/issues/569
[#566]: https://github.com/dusk-network/rusk/issues/566
[#554]: https://github.com/dusk-network/rusk/issues/554
[#547]: https://github.com/dusk-network/rusk/issues/547
[#539]: https://github.com/dusk-network/rusk/issues/539
[#520]: https://github.com/dusk-network/rusk/issues/520
[#507]: https://github.com/dusk-network/rusk/issues/507
[#505]: https://github.com/dusk-network/rusk/issues/505
[#499]: https://github.com/dusk-network/rusk/issues/499
[#495]: https://github.com/dusk-network/rusk/issues/495
[#492]: https://github.com/dusk-network/rusk/issues/492
[#482]: https://github.com/dusk-network/rusk/issues/482
[#479]: https://github.com/dusk-network/rusk/issues/479

<!-- Releases -->

[unreleased]: https://github.com/dusk-network/wallet-cli/compare/v0.11.1...HEAD
[0.11.1]: https://github.com/dusk-network/wallet-cli/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/dusk-network/wallet-cli/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/dusk-network/wallet-cli/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/dusk-network/wallet-cli/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/dusk-network/wallet-cli/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/dusk-network/wallet-cli/compare/v0.5.2...v0.7.0
[0.5.2]: https://github.com/dusk-network/wallet-cli/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/dusk-network/wallet-cli/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/dusk-network/wallet-cli/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/dusk-network/wallet-cli/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/dusk-network/wallet-cli/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/dusk-network/wallet-cli/compare/v0.2.5...v0.3.0
[0.2.5]: https://github.com/dusk-network/wallet-cli/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/dusk-network/wallet-cli/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/dusk-network/wallet-cli/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/dusk-network/wallet-cli/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/dusk-network/wallet-cli/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/dusk-network/wallet-cli/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/dusk-network/wallet-cli/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/dusk-network/wallet-cli/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/dusk-network/wallet-cli/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/dusk-network/wallet-cli/releases/tag/v0.1.0
