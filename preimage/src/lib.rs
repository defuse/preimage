//! The crate-level documentation is this repository's README, included so its code
//! examples are compiled by `cargo test` and cannot rot unnoticed.
#![doc = include_str!("../../README.md")]

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
