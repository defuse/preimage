//! Tiger hash algorithm implementation.
//!
//! Tiger is a cryptographic hash function designed by Ross Anderson and Eli Biham
//! in 1995. It produces a 192-bit hash value and was designed for 64-bit platforms.
//!
//! This module supports:
//! - Tiger with 3 passes (standard): tiger192,3, tiger160,3, tiger128,3
//! - Tiger with 4 passes: tiger192,4, tiger160,4, tiger128,4
//!
//! The output lengths (128, 160, 192) are truncations of the full 192-bit hash.
//!
//! This implementation matches PHP's hash() function output exactly.

mod tiger4;

// Re-export the 192-bit implementations
pub use tiger4::{tiger192_3, tiger192_4};

/// Tiger-160 with 3 passes.
/// Returns first 160 bits (20 bytes) of Tiger-192.
pub fn tiger160_3(data: &[u8]) -> [u8; 20] {
    let full = tiger192_3(data);
    let mut output = [0u8; 20];
    output.copy_from_slice(&full[..20]);
    output
}

/// Tiger-128 with 3 passes.
/// Returns first 128 bits (16 bytes) of Tiger-192.
pub fn tiger128_3(data: &[u8]) -> [u8; 16] {
    let full = tiger192_3(data);
    let mut output = [0u8; 16];
    output.copy_from_slice(&full[..16]);
    output
}

/// Tiger-160 with 4 passes.
/// Returns first 160 bits (20 bytes) of Tiger-192.
pub fn tiger160_4(data: &[u8]) -> [u8; 20] {
    let full = tiger192_4(data);
    let mut output = [0u8; 20];
    output.copy_from_slice(&full[..20]);
    output
}

/// Tiger-128 with 4 passes.
/// Returns first 128 bits (16 bytes) of Tiger-192.
pub fn tiger128_4(data: &[u8]) -> [u8; 16] {
    let full = tiger192_4(data);
    let mut output = [0u8; 16];
    output.copy_from_slice(&full[..16]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors verified against PHP's hash() function (defuse.ca/checksums.htm)

    // Tiger-128,3
    #[test]
    fn test_tiger128_3_empty() {
        assert_eq!(hex::encode(tiger128_3(b"")), "3293ac630c13f0245f92bbb1766e1616");
    }
    #[test]
    fn test_tiger128_3_hello() {
        assert_eq!(hex::encode(tiger128_3(b"hello")), "2cfd7f6f336288a7f2741b9bf874388a");
    }
    #[test]
    fn test_tiger128_3_emoji() {
        assert_eq!(hex::encode(tiger128_3("😀".as_bytes())), "baec5c095befb1f734b6f730798817b5");
    }

    // Tiger-128,4
    #[test]
    fn test_tiger128_4_empty() {
        assert_eq!(hex::encode(tiger128_4(b"")), "24cc78a7f6ff3546e7984e59695ca13d");
    }
    #[test]
    fn test_tiger128_4_hello() {
        assert_eq!(hex::encode(tiger128_4(b"hello")), "e8e50e239f932a1c357194e5ead0f528");
    }
    #[test]
    fn test_tiger128_4_emoji() {
        assert_eq!(hex::encode(tiger128_4("😀".as_bytes())), "63c65f81c685fb695b7018f91e5b3885");
    }

    // Tiger-160,3
    #[test]
    fn test_tiger160_3_empty() {
        assert_eq!(hex::encode(tiger160_3(b"")), "3293ac630c13f0245f92bbb1766e16167a4e5849");
    }
    #[test]
    fn test_tiger160_3_hello() {
        assert_eq!(hex::encode(tiger160_3(b"hello")), "2cfd7f6f336288a7f2741b9bf874388a54026639");
    }
    #[test]
    fn test_tiger160_3_emoji() {
        assert_eq!(hex::encode(tiger160_3("😀".as_bytes())), "baec5c095befb1f734b6f730798817b5a8724214");
    }

    // Tiger-160,4
    #[test]
    fn test_tiger160_4_empty() {
        assert_eq!(hex::encode(tiger160_4(b"")), "24cc78a7f6ff3546e7984e59695ca13d804e0b68");
    }
    #[test]
    fn test_tiger160_4_hello() {
        assert_eq!(hex::encode(tiger160_4(b"hello")), "e8e50e239f932a1c357194e5ead0f528dc2aebfe");
    }
    #[test]
    fn test_tiger160_4_emoji() {
        assert_eq!(hex::encode(tiger160_4("😀".as_bytes())), "63c65f81c685fb695b7018f91e5b38850d30cfde");
    }

    // Tiger-192,3
    #[test]
    fn test_tiger192_3_empty() {
        assert_eq!(hex::encode(tiger192_3(b"")), "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3");
    }
    #[test]
    fn test_tiger192_3_hello() {
        assert_eq!(hex::encode(tiger192_3(b"hello")), "2cfd7f6f336288a7f2741b9bf874388a54026639cadb7bf2");
    }
    #[test]
    fn test_tiger192_3_emoji() {
        assert_eq!(hex::encode(tiger192_3("😀".as_bytes())), "baec5c095befb1f734b6f730798817b5a87242145188a49e");
    }

    // Tiger-192,4
    #[test]
    fn test_tiger192_4_empty() {
        assert_eq!(hex::encode(tiger192_4(b"")), "24cc78a7f6ff3546e7984e59695ca13d804e0b686e255194");
    }
    #[test]
    fn test_tiger192_4_hello() {
        assert_eq!(hex::encode(tiger192_4(b"hello")), "e8e50e239f932a1c357194e5ead0f528dc2aebfeaed01c74");
    }
    #[test]
    fn test_tiger192_4_emoji() {
        assert_eq!(hex::encode(tiger192_4("😀".as_bytes())), "63c65f81c685fb695b7018f91e5b38850d30cfde316252a2");
    }
}
