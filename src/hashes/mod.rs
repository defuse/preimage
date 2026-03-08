mod standard;
mod ntlm;
mod lm;
mod compound;

pub use standard::{Md2, Md4, Md5, Sha1, Sha224, Sha256, Sha384, Sha512, Whirlpool, Ripemd160};
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

impl<T: HashAlgorithm + ?Sized> HashAlgorithm for Box<T> {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        (**self).hash(input)
    }

    fn name(&self) -> &str {
        (**self).name()
    }
}

