//! LM hash: the legacy LAN Manager password hash.
//!
//! WARNING: Not for cryptographic use. This crate deliberately includes insecure
//! hash functions, and none of these implementations has had a security review.
//! It is for password cracking and interoperability with old systems — do not use
//! it to protect anything.

use crate::HashAlgorithm;
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;

/// LAN Manager hash.
///
/// Uppercase input, pad to 14 bytes, split into two 7-byte halves,
/// expand each to an 8-byte DES key, DES-ECB encrypt `"KGS!@#$%"`,
/// concatenate the two 8-byte ciphertexts.
///
/// # Divergence from Windows, for non-ASCII input
///
/// Real LM uppercases the password in the machine's **OEM code page** (CP437, CP850
/// and so on) before hashing. This implementation folds ASCII `a`–`z` bytewise and
/// passes every other byte through unchanged, so for any password containing a byte
/// outside ASCII the digest **will not match the one Windows computed**, and a hash
/// captured from a Windows system will not be found by searching an index built with
/// this. ASCII passwords — the overwhelming majority of what LM was ever used for, and
/// what a 14-character uppercase-only scheme mostly contains — are unaffected.
///
/// This is deliberate: it reproduces the `LMHashAlgorithm` in the PHP implementation
/// these indexes descend from, which does `strtoupper(substr($string, 0, 14))` with no
/// code-page conversion either. Matching that is what keeps a Rust-built index and a
/// PHP-built index interchangeable, which is the point of this crate. Verified against
/// that implementation across ten inputs including multi-byte UTF-8, raw non-UTF-8
/// bytes, high bytes, and both sides of the 14-byte truncation — see the tests below.
///
/// So the divergence is inherited rather than introduced, and fixing it here alone
/// would break compatibility with every existing index without making a single extra
/// password crackable.
pub struct Lm;

const KGS_CONSTANT: [u8; 8] = *b"KGS!@#$%";

impl HashAlgorithm for Lm {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        // Uppercase and truncate to 14 bytes, then pad with nulls.
        // The PHP code uses strtoupper(substr($string, 0, 14)) which operates
        // on bytes, so we do the same — this is ASCII uppercasing only.
        let mut password = [0u8; 14];
        let upper: Vec<u8> = input.iter().map(|&b| b.to_ascii_uppercase()).collect();
        let copy_len = upper.len().min(14);
        password[..copy_len].copy_from_slice(&upper[..copy_len]);

        let p1 = lm_des_encrypt(&password[0..7]);
        let p2 = lm_des_encrypt(&password[7..14]);

        let mut result = Vec::with_capacity(16);
        result.extend_from_slice(&p1);
        result.extend_from_slice(&p2);
        Some(result)
    }

    fn name(&self) -> &str {
        "LM"
    }
}

/// Expand 7 bytes to an 8-byte DES key (with parity bits) and encrypt the KGS constant.
fn lm_des_encrypt(half: &[u8]) -> [u8; 8] {
    assert_eq!(half.len(), 7, "LM half must be exactly 7 bytes");

    // Expand 56 bits to 64 bits matching the PHP/C key schedule exactly.
    // Each output byte uses 7 data bits and 1 parity bit (LSB).
    let mut key = [0u8; 8];
    key[0] = half[0] & 0xFE;
    key[1] = ((half[0] << 7) | (half[1] >> 1)) & 0xFE;
    key[2] = ((half[1] << 6) | (half[2] >> 2)) & 0xFE;
    key[3] = ((half[2] << 5) | (half[3] >> 3)) & 0xFE;
    key[4] = ((half[3] << 4) | (half[4] >> 4)) & 0xFE;
    key[5] = ((half[4] << 3) | (half[5] >> 5)) & 0xFE;
    key[6] = ((half[5] << 2) | (half[6] >> 6)) & 0xFE;
    key[7] = (half[6] << 1) & 0xFE;

    // Set odd parity for each byte (matching openssl DES key parity).
    for byte in &mut key {
        let ones = byte.count_ones();
        if ones % 2 == 0 {
            *byte |= 1;
        }
    }

    let cipher = Des::new_from_slice(&key).expect("DES key is always 8 bytes");
    let mut block = KGS_CONSTANT.into();
    cipher.encrypt_block(&mut block);
    block.into()
}

#[cfg(test)]
mod tests {
    /// Vectors from the reference `LMHashAlgorithm` in crackstation-hashdb's
    /// MoreHashes.php, run under PHP 8.4.23. Its `LMhash_DESencrypt` calls
    /// `openssl_encrypt(.., "des-ecb", ..)`, and DES lives in OpenSSL 3's legacy
    /// provider, so generating these needs an `openssl.cnf` that activates `legacy` --
    /// without it PHP returns `false` and every vector comes back empty.
    ///
    /// These are what the `Lm` docs mean by "verified against that implementation": the
    /// claim is that this matches PHP byte for byte *including* on input neither handles
    /// the way Windows would, which is why the non-ASCII cases are here rather than just
    /// `"password"`.
    fn lm_hex(input: &[u8]) -> String {
        Lm.hash(input)
            .expect("LM accepts any input")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[test]
    fn matches_php_on_ascii_and_truncation() {
        // The canonical empty-input LM hash, and a check that PHP agrees.
        assert_eq!(lm_hex(b""), "aad3b435b51404eeaad3b435b51404ee");
        assert_eq!(lm_hex(b"password"), "e52cac67419a9a224a3b108f3fa6cb6d");
        // Case is folded, so these are the same password to LM.
        assert_eq!(lm_hex(b"PassWord123"), "e52cac67419a9a22664345140a852f61");
        // Everything past 14 bytes is discarded, so these two agree.
        assert_eq!(
            lm_hex(b"ABCDEFGHIJKLMN"),
            "e0c510199cc66abd8c51ec214bebdea1"
        );
        assert_eq!(
            lm_hex(b"ABCDEFGHIJKLMNO"),
            "e0c510199cc66abd8c51ec214bebdea1"
        );
        assert_eq!(
            lm_hex(b"thisisaverylongpasswordindeed"),
            "8a6d8380cac58f224781f57dee2192bc"
        );
    }

    /// The divergence documented on `Lm`. Windows would uppercase these in an OEM code
    /// page first and get different digests; PHP does not, and neither do we. Pinning
    /// the PHP values is what keeps a Rust-built index interchangeable with a PHP-built
    /// one -- if this ever starts matching Windows instead, every existing index breaks,
    /// and these tests are where that shows up.
    #[test]
    fn matches_php_on_input_windows_would_treat_differently() {
        assert_eq!(
            lm_hex("p\u{e4}ssw\u{f6}rd".as_bytes()),
            "1141628eb0e6e72ef3343f26aac0ef2f"
        );
        assert_eq!(
            lm_hex(b"\xff\xfe\x00binary"),
            "9cea3785d00e0c6ffa3975b08bc884c1"
        );
        assert_eq!(lm_hex(b"\xe0\xe1\xe2"), "ff78ac5231283bbcaad3b435b51404ee");
        // Latin-1 lowercase accented bytes: PHP's strtoupper leaves them alone.
        assert_eq!(lm_hex(b"\xe9\xe8"), "5695e143a4de61c2aad3b435b51404ee");
    }

    use super::*;

    #[test]
    fn test_lm_empty() {
        let hash = Lm.hash(b"").expect("LM should not fail");
        assert_eq!(hex::encode(&hash), "aad3b435b51404eeaad3b435b51404ee");
    }

    #[test]
    fn test_lm_password() {
        let hash = Lm.hash(b"PASSWORD").expect("LM should not fail");
        assert_eq!(hex::encode(&hash), "e52cac67419a9a224a3b108f3fa6cb6d");
    }

    #[test]
    fn test_lm_lowercase_uppercased() {
        // LM uppercases the input, so "password" == "PASSWORD"
        let lower = Lm.hash(b"password").expect("should not fail");
        let upper = Lm.hash(b"PASSWORD").expect("should not fail");
        assert_eq!(lower, upper);
    }

    #[test]
    fn test_lm_hello() {
        let hash = Lm.hash(b"hello").expect("should not fail");
        assert_eq!(hex::encode(&hash), "fda95fbeca288d44aad3b435b51404ee");
    }

    #[test]
    fn test_lm_emoji() {
        // LM treats emoji as raw bytes, uppercases byte-by-byte (no-op for high bytes)
        let hash = Lm.hash("😀".as_bytes()).expect("should not fail");
        assert_eq!(hex::encode(&hash), "727f6a04bfb4f99faad3b435b51404ee");
    }

    #[test]
    fn test_lm_truncation() {
        // LM only uses first 14 characters
        let short = Lm.hash(b"12345678901234").expect("should not fail");
        let long = Lm.hash(b"12345678901234extra").expect("should not fail");
        assert_eq!(short, long);
    }
}
