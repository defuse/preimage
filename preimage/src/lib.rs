pub mod entry;
mod index;
pub(crate) mod oracle;

// Re-export from allthehashes
pub use allthehashes::{HashAlgorithm, get_algorithm, ALGORITHM_NAMES};
// Re-export hash implementations for tests and library users
pub use allthehashes::{
    Md5, Md5Md5, MySql41, Ntlm, Lm, Sha1, Sha256, Whirlpool,
    MD5, MD5MD5, MYSQL41, NTLM, LM, SHA1, SHA256, WHIRLPOOL,
};

pub use index::IndexFile;
pub use index::lookup::{LookupTable, LookupMatch};
pub use oracle::{PreimageOracle, OracleMatch, HashResult};
