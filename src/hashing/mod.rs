mod standard;
mod ntlm;
mod lm;
mod compound;

pub use standard::{Md5, Sha1, Sha224, Sha256, Sha384, Sha512, Whirlpool, Ripemd160};
pub use ntlm::Ntlm;
pub use lm::Lm;
pub use compound::{Md5Md5, MySql41, QubesV31};

/// Trait for hash algorithm implementations.
///
/// Implementations must be `Send + Sync` for use in multi-table lookups.
/// Library users can implement this trait for custom hash algorithms.
pub trait HashAlgorithm: Send + Sync {
    /// Compute the hash of the input bytes.
    ///
    /// Returns `None` if the input is invalid for this algorithm
    /// (e.g. NTLM with non-UTF-8 input).
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>>;

    /// Human-readable algorithm name matching the original PHP names exactly.
    fn name(&self) -> &str;
}

/// Look up a built-in algorithm by its canonical name (case-sensitive).
///
/// This is intended for the CLI binary. Library users should construct
/// algorithm types directly (e.g. `Md5`, `Sha1`).
pub fn get_algorithm(name: &str) -> Option<Box<dyn HashAlgorithm>> {
    match name {
        "md5" => Some(Box::new(Md5)),
        "sha1" => Some(Box::new(Sha1)),
        "sha224" => Some(Box::new(Sha224)),
        "sha256" => Some(Box::new(Sha256)),
        "sha384" => Some(Box::new(Sha384)),
        "sha512" => Some(Box::new(Sha512)),
        "whirlpool" => Some(Box::new(Whirlpool)),
        "ripemd160" => Some(Box::new(Ripemd160)),
        "NTLM" => Some(Box::new(Ntlm)),
        "LM" => Some(Box::new(Lm)),
        "md5(md5)" => Some(Box::new(Md5Md5)),
        "MySQL4.1+" => Some(Box::new(MySql41)),
        "QubesV3.1BackupDefaults" => Some(Box::new(QubesV31)),
        _ => None,
    }
}

/// Return a list of all supported algorithm names.
pub fn list_algorithms() -> Vec<&'static str> {
    vec![
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "whirlpool",
        "ripemd160",
        "LM",
        "NTLM",
        "md5(md5)",
        "MySQL4.1+",
        "QubesV3.1BackupDefaults",
    ]
}
