use digest::Digest;
use crate::HashAlgorithm;

/// NTLM hash: UTF-8 → UTF-16LE → MD4.
///
/// Returns `None` for invalid UTF-8 input (matching PHP's `iconv` returning false).
pub struct Ntlm;

impl HashAlgorithm for Ntlm {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        let input_str = std::str::from_utf8(input).ok()?;

        let mut utf16_bytes = Vec::with_capacity(input_str.len() * 2);
        for code_unit in input_str.encode_utf16() {
            utf16_bytes.extend_from_slice(&code_unit.to_le_bytes());
        }

        let mut hasher = md4::Md4::new();
        hasher.update(&utf16_bytes);
        Some(hasher.finalize().to_vec())
    }

    fn name(&self) -> &str {
        "NTLM"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors verified against PHP: hash("md4", mb_convert_encoding($s, "UTF-16LE", "UTF-8"))

    #[test]
    fn test_ntlm_empty() {
        let hash = Ntlm.hash(b"").expect("empty string is valid UTF-8");
        assert_eq!(hex::encode(&hash), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn test_ntlm_hello() {
        let hash = Ntlm.hash(b"hello").expect("should succeed");
        assert_eq!(hex::encode(&hash), "066ddfd4ef0e9cd7c256fe77191ef43c");
    }

    #[test]
    fn test_ntlm_emoji() {
        let hash = Ntlm.hash("😀".as_bytes()).expect("emoji is valid UTF-8");
        assert_eq!(hex::encode(&hash), "4b58a10cc20a4e7d808d218e1f80aabc");
    }

    #[test]
    fn test_ntlm_password() {
        let hash = Ntlm.hash(b"password").expect("should succeed");
        assert_eq!(hex::encode(&hash), "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn test_ntlm_invalid_utf8() {
        let invalid = &[0xFF, 0xFE];
        assert!(Ntlm.hash(invalid).is_none());
    }
}
