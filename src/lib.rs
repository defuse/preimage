pub mod entry;
pub mod hashing;
#[cfg(feature = "cli")]
pub mod builder;
#[cfg(feature = "cli")]
pub mod sorter;
#[cfg(feature = "cli")]
pub mod checker;
pub mod lookup;
pub mod oracle;

pub use hashing::{HashAlgorithm, get_algorithm, list_algorithms};
pub use lookup::{LookupTable, LookupMatch};
pub use oracle::{PreimageOracle, OracleMatch, HashResult};
#[cfg(feature = "cli")]
pub use builder::IndexBuilder;
#[cfg(feature = "cli")]
pub use sorter::IndexSorter;
#[cfg(feature = "cli")]
pub use checker::check_sorted;
