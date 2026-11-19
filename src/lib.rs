//! The `rad backup` archive format, and with the default `cli` feature the `rad-backup` command
//! line on top of it.
//!
//! Without default features the library reads and writes archives over byte streams and
//! touches no file system, process or terminal, so it builds for `wasm32-unknown-unknown`.
//! `ARCHIVE-FORMAT.md` is the format's specification.
//!
//! A `wasm32-unknown-unknown` build needs two things this crate leaves to its consumer. One is
//! a backend for `getrandom` 0.2, which age draws salts and keys from. In a browser, the
//! consumer depends on `getrandom` 0.2 with its `js` feature. Elsewhere, it registers a source
//! with the `custom` feature. The other is a clang that targets wasm32 and an `llvm-ar`, for
//! zstd's C, named by `CC_wasm32_unknown_unknown` and `AR_wasm32_unknown_unknown` when the
//! defaults cannot.
//!
//! Items that exist only with the `cli` feature serve the `rad-backup` binary and carry no
//! stability promise.
//!
//! The format lets a writer add manifest keys and words. A new key is a new field in a
//! `manifest` struct, and a new word for `tier` or `repoSelection` is a new enum variant. Either
//! breaks code that builds the struct or matches the enum, so it ships in a breaking release.

// `ci/wasm.sh` lints this build, so a call the browser cannot make fails there and not in a tab
#![cfg_attr(
    not(feature = "cli"),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types
    )
)]

pub mod archives;
pub mod container;
pub mod credits;
pub mod crypt;
pub mod error;
pub mod instructions;
pub mod key;
pub mod manifest;

#[cfg(feature = "cli")]
mod app;
#[cfg(feature = "cli")]
mod cli;
#[cfg(feature = "cli")]
mod cmd;
#[cfg(feature = "cli")]
mod db;
#[cfg(feature = "cli")]
mod exec;
#[cfg(feature = "cli")]
mod git;
#[cfg(feature = "cli")]
mod home;
#[cfg(feature = "cli")]
mod inventory;
#[cfg(feature = "cli")]
mod man;
#[cfg(feature = "cli")]
mod perms;
#[cfg(feature = "cli")]
mod rad;
#[cfg(feature = "cli")]
mod state;
#[cfg(feature = "cli")]
mod term;

/// Runs `rad-backup` with this process's arguments and environment.
#[cfg(feature = "cli")]
pub use app::main;
