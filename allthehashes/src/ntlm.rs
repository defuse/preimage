//! NTLM hash: UTF-8 to UTF-16LE, then MD4.
//!
//! WARNING: Not for cryptographic use. This crate deliberately includes insecure
//! hash functions, and none of these implementations has had a security review.
//! It is for password cracking and interoperability with old systems — do not use
//! it to protect anything.

use crate::HashAlgorithm;
use digest::Digest;

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

    // Vectors verified against the PHP reference this port reproduces --
    // `MoreHashAlgorithms::GetHashFunction("NTLM")` in crackstation-hashdb's
    // MoreHashes.php, which is `hash("md4", iconv("UTF-8", "UTF-16LE", $s))`.
    //
    // Deliberately not `mb_convert_encoding`: it substitutes invalid sequences rather
    // than failing, so it hashes input `iconv` rejects. The four valid-UTF-8 vectors
    // below are identical under both, but 0xFF 0xFE is `false` under `iconv` and
    // afe43055c4092b6daca53347a5b4d9e2 under `mb_convert_encoding` -- so that function
    // would contradict `test_ntlm_rejects_invalid_utf8`, the one test here that pins the
    // behaviour deciding whether a word gets an index entry at all.

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

    /// Every one of these is `false` from the PHP reference, and so must be `None` here:
    /// a UTF-16 BOM read as UTF-8, a lone continuation-less 0xFF, and a truncated
    /// multi-byte sequence (the "caf\xC3" tail of "caf\u{e9}").
    #[test]
    fn test_ntlm_rejects_invalid_utf8() {
        for invalid in [&[0xFF, 0xFE][..], &[0xFF][..], b"caf\xC3"] {
            assert_eq!(
                Ntlm.hash(invalid),
                None,
                "input {invalid:02x?} must not hash"
            );
        }
    }
}
