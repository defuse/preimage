mod standard;
mod ntlm;
mod lm;
mod compound;
mod snefru;
mod tiger;
mod haval;
mod checksums;

pub use standard::{
    Md2, Md4, Md5, Sha1, Sha224, Sha256, Sha384, Sha512,
    Sha512_224, Sha512_256,
    Sha3_224, Sha3_256, Sha3_384, Sha3_512,
    Whirlpool,
    Ripemd128, Ripemd160, Ripemd256, Ripemd320,
    Gost94Test, Gost94CryptoPro,
};
pub use ntlm::Ntlm;
pub use lm::Lm;
pub use compound::{Md5Md5, MySql41, QubesV31};
pub use checksums::{Adler32, Crc32, Crc32b, Crc32c, Fnv132, Fnv164, Fnv1a32, Fnv1a64, Joaat};

// Wrapper structs for custom hash implementations
macro_rules! custom_hash {
    ($struct_name:ident, $php_name:expr, $func:path, $output_size:expr) => {
        pub struct $struct_name;
        impl HashAlgorithm for $struct_name {
            fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
                Some($func(input).to_vec())
            }
            fn name(&self) -> &str {
                $php_name
            }
        }
    };
}

// Snefru (snefru and snefru256 are the same algorithm)
custom_hash!(Snefru, "snefru", snefru::snefru256, 32);
custom_hash!(Snefru256, "snefru256", snefru::snefru256, 32);

// Tiger variants
custom_hash!(Tiger128_3, "tiger128,3", tiger::tiger128_3, 16);
custom_hash!(Tiger160_3, "tiger160,3", tiger::tiger160_3, 20);
custom_hash!(Tiger192_3, "tiger192,3", tiger::tiger192_3, 24);
custom_hash!(Tiger128_4, "tiger128,4", tiger::tiger128_4, 16);
custom_hash!(Tiger160_4, "tiger160,4", tiger::tiger160_4, 20);
custom_hash!(Tiger192_4, "tiger192,4", tiger::tiger192_4, 24);

// HAVAL variants (output_bits, passes)
custom_hash!(Haval128_3, "haval128,3", haval::haval128_3, 16);
custom_hash!(Haval128_4, "haval128,4", haval::haval128_4, 16);
custom_hash!(Haval128_5, "haval128,5", haval::haval128_5, 16);
custom_hash!(Haval160_3, "haval160,3", haval::haval160_3, 20);
custom_hash!(Haval160_4, "haval160,4", haval::haval160_4, 20);
custom_hash!(Haval160_5, "haval160,5", haval::haval160_5, 20);
custom_hash!(Haval192_3, "haval192,3", haval::haval192_3, 24);
custom_hash!(Haval192_4, "haval192,4", haval::haval192_4, 24);
custom_hash!(Haval192_5, "haval192,5", haval::haval192_5, 24);
custom_hash!(Haval224_3, "haval224,3", haval::haval224_3, 28);
custom_hash!(Haval224_4, "haval224,4", haval::haval224_4, 28);
custom_hash!(Haval224_5, "haval224,5", haval::haval224_5, 28);
custom_hash!(Haval256_3, "haval256,3", haval::haval256_3, 32);
custom_hash!(Haval256_4, "haval256,4", haval::haval256_4, 32);
custom_hash!(Haval256_5, "haval256,5", haval::haval256_5, 32);

// Static algorithm references — zero heap allocation, just a pointer to a vtable.
// Original algorithms
pub static MD2: &dyn HashAlgorithm = &Md2;
pub static MD4: &dyn HashAlgorithm = &Md4;
pub static MD5: &dyn HashAlgorithm = &Md5;
pub static SHA1: &dyn HashAlgorithm = &Sha1;
pub static SHA224: &dyn HashAlgorithm = &Sha224;
pub static SHA256: &dyn HashAlgorithm = &Sha256;
pub static SHA384: &dyn HashAlgorithm = &Sha384;
pub static SHA512: &dyn HashAlgorithm = &Sha512;
pub static WHIRLPOOL: &dyn HashAlgorithm = &Whirlpool;
pub static RIPEMD160: &dyn HashAlgorithm = &Ripemd160;
pub static LM: &dyn HashAlgorithm = &Lm;
pub static NTLM: &dyn HashAlgorithm = &Ntlm;
pub static MD5MD5: &dyn HashAlgorithm = &Md5Md5;
pub static MYSQL41: &dyn HashAlgorithm = &MySql41;
pub static QUBESV31: &dyn HashAlgorithm = &QubesV31;

// New SHA-2 variants
pub static SHA512_224: &dyn HashAlgorithm = &Sha512_224;
pub static SHA512_256: &dyn HashAlgorithm = &Sha512_256;

// SHA-3 family
pub static SHA3_224: &dyn HashAlgorithm = &Sha3_224;
pub static SHA3_256: &dyn HashAlgorithm = &Sha3_256;
pub static SHA3_384: &dyn HashAlgorithm = &Sha3_384;
pub static SHA3_512: &dyn HashAlgorithm = &Sha3_512;

// Additional RIPEMD variants
pub static RIPEMD128: &dyn HashAlgorithm = &Ripemd128;
pub static RIPEMD256: &dyn HashAlgorithm = &Ripemd256;
pub static RIPEMD320: &dyn HashAlgorithm = &Ripemd320;

// GOST
pub static GOST94TEST: &dyn HashAlgorithm = &Gost94Test;
pub static GOST94CRYPTOPRO: &dyn HashAlgorithm = &Gost94CryptoPro;

// Snefru
pub static SNEFRU: &dyn HashAlgorithm = &Snefru;
pub static SNEFRU256: &dyn HashAlgorithm = &Snefru256;

// Tiger
pub static TIGER128_3: &dyn HashAlgorithm = &Tiger128_3;
pub static TIGER160_3: &dyn HashAlgorithm = &Tiger160_3;
pub static TIGER192_3: &dyn HashAlgorithm = &Tiger192_3;
pub static TIGER128_4: &dyn HashAlgorithm = &Tiger128_4;
pub static TIGER160_4: &dyn HashAlgorithm = &Tiger160_4;
pub static TIGER192_4: &dyn HashAlgorithm = &Tiger192_4;

// HAVAL
pub static HAVAL128_3: &dyn HashAlgorithm = &Haval128_3;
pub static HAVAL128_4: &dyn HashAlgorithm = &Haval128_4;
pub static HAVAL128_5: &dyn HashAlgorithm = &Haval128_5;
pub static HAVAL160_3: &dyn HashAlgorithm = &Haval160_3;
pub static HAVAL160_4: &dyn HashAlgorithm = &Haval160_4;
pub static HAVAL160_5: &dyn HashAlgorithm = &Haval160_5;
pub static HAVAL192_3: &dyn HashAlgorithm = &Haval192_3;
pub static HAVAL192_4: &dyn HashAlgorithm = &Haval192_4;
pub static HAVAL192_5: &dyn HashAlgorithm = &Haval192_5;
pub static HAVAL224_3: &dyn HashAlgorithm = &Haval224_3;
pub static HAVAL224_4: &dyn HashAlgorithm = &Haval224_4;
pub static HAVAL224_5: &dyn HashAlgorithm = &Haval224_5;
pub static HAVAL256_3: &dyn HashAlgorithm = &Haval256_3;
pub static HAVAL256_4: &dyn HashAlgorithm = &Haval256_4;
pub static HAVAL256_5: &dyn HashAlgorithm = &Haval256_5;

// Non-crypto checksums
pub static ADLER32: &dyn HashAlgorithm = &Adler32;
pub static CRC32: &dyn HashAlgorithm = &Crc32;
pub static CRC32B: &dyn HashAlgorithm = &Crc32b;
pub static CRC32C: &dyn HashAlgorithm = &Crc32c;
pub static FNV132: &dyn HashAlgorithm = &Fnv132;
pub static FNV164: &dyn HashAlgorithm = &Fnv164;
pub static FNV1A32: &dyn HashAlgorithm = &Fnv1a32;
pub static FNV1A64: &dyn HashAlgorithm = &Fnv1a64;
pub static JOAAT: &dyn HashAlgorithm = &Joaat;

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

