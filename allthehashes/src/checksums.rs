//! Non-cryptographic checksums and hashes.
//!
//! These are fast checksums not designed for security, but included for
//! compatibility with PHP's hash() function.

use crate::HashAlgorithm;
use crc::{Crc, CRC_32_BZIP2, CRC_32_ISCSI, CRC_32_ISO_HDLC};

// =============================================================================
// Adler-32
// =============================================================================

pub struct Adler32;

impl HashAlgorithm for Adler32 {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        let checksum = adler2::adler32_slice(input);
        Some(checksum.to_be_bytes().to_vec())
    }

    fn name(&self) -> &str {
        "adler32"
    }
}

// =============================================================================
// CRC-32 variants
// =============================================================================

/// CRC-32 - PHP's hash('crc32') uses CRC-32/BZIP2 (non-reflected), output in big-endian
pub struct Crc32;

impl HashAlgorithm for Crc32 {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        let crc = Crc::<u32>::new(&CRC_32_BZIP2);
        let checksum = crc.checksum(input).swap_bytes();
        Some(checksum.to_be_bytes().to_vec())
    }

    fn name(&self) -> &str {
        "crc32"
    }
}

/// CRC-32B - PHP's hash('crc32b') uses CRC-32/ISO-HDLC (reflected, same as zlib)
pub struct Crc32b;

impl HashAlgorithm for Crc32b {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
        let checksum = crc.checksum(input);
        Some(checksum.to_be_bytes().to_vec())
    }

    fn name(&self) -> &str {
        "crc32b"
    }
}

/// CRC-32C - PHP's hash('crc32c') uses CRC-32/ISCSI (Castagnoli polynomial)
pub struct Crc32c;

impl HashAlgorithm for Crc32c {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        let crc = Crc::<u32>::new(&CRC_32_ISCSI);
        let checksum = crc.checksum(input);
        Some(checksum.to_be_bytes().to_vec())
    }

    fn name(&self) -> &str {
        "crc32c"
    }
}

// =============================================================================
// FNV (Fowler-Noll-Vo) hash
// =============================================================================

const FNV1_32_INIT: u32 = 0x811c9dc5;
const FNV1_32_PRIME: u32 = 0x01000193;
const FNV1_64_INIT: u64 = 0xcbf29ce484222325;
const FNV1_64_PRIME: u64 = 0x00000100000001B3;

/// FNV-1 32-bit hash
pub struct Fnv132;

impl HashAlgorithm for Fnv132 {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        let mut hash = FNV1_32_INIT;
        for &byte in input {
            hash = hash.wrapping_mul(FNV1_32_PRIME);
            hash ^= byte as u32;
        }
        Some(hash.to_be_bytes().to_vec())
    }

    fn name(&self) -> &str {
        "fnv132"
    }
}

/// FNV-1 64-bit hash
pub struct Fnv164;

impl HashAlgorithm for Fnv164 {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        let mut hash = FNV1_64_INIT;
        for &byte in input {
            hash = hash.wrapping_mul(FNV1_64_PRIME);
            hash ^= byte as u64;
        }
        Some(hash.to_be_bytes().to_vec())
    }

    fn name(&self) -> &str {
        "fnv164"
    }
}

/// FNV-1a 32-bit hash (XOR before multiply)
pub struct Fnv1a32;

impl HashAlgorithm for Fnv1a32 {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        let mut hash = FNV1_32_INIT;
        for &byte in input {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(FNV1_32_PRIME);
        }
        Some(hash.to_be_bytes().to_vec())
    }

    fn name(&self) -> &str {
        "fnv1a32"
    }
}

/// FNV-1a 64-bit hash (XOR before multiply)
pub struct Fnv1a64;

impl HashAlgorithm for Fnv1a64 {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        let mut hash = FNV1_64_INIT;
        for &byte in input {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV1_64_PRIME);
        }
        Some(hash.to_be_bytes().to_vec())
    }

    fn name(&self) -> &str {
        "fnv1a64"
    }
}

// =============================================================================
// Jenkins One-at-a-time hash
// =============================================================================

pub struct Joaat;

impl HashAlgorithm for Joaat {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        let mut hash: u32 = 0;
        for &byte in input {
            hash = hash.wrapping_add(byte as u32);
            hash = hash.wrapping_add(hash << 10);
            hash ^= hash >> 6;
        }
        hash = hash.wrapping_add(hash << 3);
        hash ^= hash >> 11;
        hash = hash.wrapping_add(hash << 15);
        Some(hash.to_be_bytes().to_vec())
    }

    fn name(&self) -> &str {
        "joaat"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors verified against PHP's hash() function (defuse.ca/checksums.htm)

    // Adler-32
    #[test]
    fn test_adler32_empty() {
        assert_eq!(hex::encode(Adler32.hash(b"").unwrap()), "00000001");
    }
    #[test]
    fn test_adler32_hello() {
        assert_eq!(hex::encode(Adler32.hash(b"hello").unwrap()), "062c0215");
    }
    #[test]
    fn test_adler32_emoji() {
        assert_eq!(
            hex::encode(Adler32.hash("😀".as_bytes()).unwrap()),
            "075102a8"
        );
    }

    // CRC-32
    #[test]
    fn test_crc32_empty() {
        assert_eq!(hex::encode(Crc32.hash(b"").unwrap()), "00000000");
    }
    #[test]
    fn test_crc32_hello() {
        assert_eq!(hex::encode(Crc32.hash(b"hello").unwrap()), "3d653119");
    }
    #[test]
    fn test_crc32_emoji() {
        assert_eq!(
            hex::encode(Crc32.hash("😀".as_bytes()).unwrap()),
            "f4ac78d9"
        );
    }

    // CRC-32B
    #[test]
    fn test_crc32b_empty() {
        assert_eq!(hex::encode(Crc32b.hash(b"").unwrap()), "00000000");
    }
    #[test]
    fn test_crc32b_hello() {
        assert_eq!(hex::encode(Crc32b.hash(b"hello").unwrap()), "3610a686");
    }
    #[test]
    fn test_crc32b_emoji() {
        assert_eq!(
            hex::encode(Crc32b.hash("😀".as_bytes()).unwrap()),
            "054db544"
        );
    }

    // CRC-32C
    #[test]
    fn test_crc32c_empty() {
        assert_eq!(hex::encode(Crc32c.hash(b"").unwrap()), "00000000");
    }
    #[test]
    fn test_crc32c_hello() {
        assert_eq!(hex::encode(Crc32c.hash(b"hello").unwrap()), "9a71bb4c");
    }
    #[test]
    fn test_crc32c_emoji() {
        assert_eq!(
            hex::encode(Crc32c.hash("😀".as_bytes()).unwrap()),
            "e3e0db74"
        );
    }

    // FNV-1 32-bit
    #[test]
    fn test_fnv132_empty() {
        assert_eq!(hex::encode(Fnv132.hash(b"").unwrap()), "811c9dc5");
    }
    #[test]
    fn test_fnv132_hello() {
        assert_eq!(hex::encode(Fnv132.hash(b"hello").unwrap()), "b6fa7167");
    }
    #[test]
    fn test_fnv132_emoji() {
        assert_eq!(
            hex::encode(Fnv132.hash("😀".as_bytes()).unwrap()),
            "fe02dc3a"
        );
    }

    // FNV-1 64-bit
    #[test]
    fn test_fnv164_empty() {
        assert_eq!(hex::encode(Fnv164.hash(b"").unwrap()), "cbf29ce484222325");
    }
    #[test]
    fn test_fnv164_hello() {
        assert_eq!(
            hex::encode(Fnv164.hash(b"hello").unwrap()),
            "7b495389bdbdd4c7"
        );
    }
    #[test]
    fn test_fnv164_emoji() {
        assert_eq!(
            hex::encode(Fnv164.hash("😀".as_bytes()).unwrap()),
            "5692bc7c3c90765a"
        );
    }

    // FNV-1a 32-bit
    #[test]
    fn test_fnv1a32_empty() {
        assert_eq!(hex::encode(Fnv1a32.hash(b"").unwrap()), "811c9dc5");
    }
    #[test]
    fn test_fnv1a32_hello() {
        assert_eq!(hex::encode(Fnv1a32.hash(b"hello").unwrap()), "4f9f2cab");
    }
    #[test]
    fn test_fnv1a32_emoji() {
        assert_eq!(
            hex::encode(Fnv1a32.hash("😀".as_bytes()).unwrap()),
            "33a29608"
        );
    }

    // FNV-1a 64-bit
    #[test]
    fn test_fnv1a64_empty() {
        assert_eq!(hex::encode(Fnv1a64.hash(b"").unwrap()), "cbf29ce484222325");
    }
    #[test]
    fn test_fnv1a64_hello() {
        assert_eq!(
            hex::encode(Fnv1a64.hash(b"hello").unwrap()),
            "a430d84680aabd0b"
        );
    }
    #[test]
    fn test_fnv1a64_emoji() {
        assert_eq!(
            hex::encode(Fnv1a64.hash("😀".as_bytes()).unwrap()),
            "feff073875020288"
        );
    }

    // Jenkins One-at-a-time
    #[test]
    fn test_joaat_empty() {
        assert_eq!(hex::encode(Joaat.hash(b"").unwrap()), "00000000");
    }
    #[test]
    fn test_joaat_hello() {
        assert_eq!(hex::encode(Joaat.hash(b"hello").unwrap()), "c8fd181b");
    }
    #[test]
    fn test_joaat_emoji() {
        assert_eq!(
            hex::encode(Joaat.hash("😀".as_bytes()).unwrap()),
            "243a5bca"
        );
    }
}
