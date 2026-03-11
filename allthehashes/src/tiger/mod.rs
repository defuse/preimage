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

    #[test]
    fn test_tiger192_3_empty() {
        let result = tiger192_3(b"");
        let expected = hex::decode("3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_tiger192_3_test() {
        let result = tiger192_3(b"test");
        let expected = hex::decode("7ab383fc29d81f8d0d68e87c69bae5f1f18266d730c48b1d").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_tiger192_4_empty() {
        let result = tiger192_4(b"");
        let expected = hex::decode("24cc78a7f6ff3546e7984e59695ca13d804e0b686e255194").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_tiger128_3_empty() {
        let result = tiger128_3(b"");
        let expected = hex::decode("3293ac630c13f0245f92bbb1766e1616").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_tiger160_3_empty() {
        let result = tiger160_3(b"");
        let expected = hex::decode("3293ac630c13f0245f92bbb1766e16167a4e5849").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }
}
