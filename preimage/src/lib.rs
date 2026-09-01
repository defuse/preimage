//! The crate-level documentation is this repository's README, included so its code
//! examples are compiled by `cargo test` and cannot rot unnoticed.
//!
//! Read through `preimage/README.md`, a symlink to the file at the repository root, and
//! not through `../../README.md`: a published crate contains nothing above its own
//! directory, so the two-level path packages fine and then fails to compile from the
//! tarball. Cargo follows the symlink and copies the real file in.
#![doc = include_str!("../README.md")]

mod index;
mod oracle;

// Re-export everything from allthehashes
pub use allthehashes::*;

/// Re-exported because it is part of this crate's public API: `IndexSorter::sort` and
/// `sort_ram_only` take `Option<&indicatif::ProgressBar>`. Without this a caller has to
/// depend on `indicatif` directly and keep its version in lockstep with ours, and a
/// mismatch produces a type error about two `ProgressBar`s that look identical.
pub use indicatif;

pub use index::entry;
pub use index::lookup::{LookupMatch, LookupOutcome, LookupTable};
pub use index::IndexFile;
pub use oracle::{HashResult, OracleMatch, PreimageOracle};
