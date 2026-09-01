//! Compound hashes: one algorithm applied over the output of another.
//!
//! WARNING: Not for cryptographic use. This crate deliberately includes insecure
//! hash functions, and none of these implementations has had a security review.
//! It is for password cracking and interoperability with old systems — do not use
//! it to protect anything.

use crate::HashAlgorithm;
use digest::Digest;
use hmac::{Hmac, Mac};

/// MD5(MD5): compute MD5, hex-encode, then MD5 the hex string.
pub struct Md5Md5;

impl HashAlgorithm for Md5Md5 {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        let mut hasher = md5::Md5::new();
        hasher.update(input);
        let first = hasher.finalize();

        let hex_str = hex::encode(first);

        let mut hasher = md5::Md5::new();
        hasher.update(hex_str.as_bytes());
        Some(hasher.finalize().to_vec())
    }

    fn name(&self) -> &str {
        "md5(md5)"
    }
}

/// MySQL 4.1+: SHA1 of the binary SHA1.
pub struct MySql41;

impl HashAlgorithm for MySql41 {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        let mut hasher = sha1::Sha1::new();
        hasher.update(input);
        let first = hasher.finalize();

        let mut hasher = sha1::Sha1::new();
        hasher.update(first);
        Some(hasher.finalize().to_vec())
    }

    fn name(&self) -> &str {
        "MySQL4.1+"
    }
}

/// Qubes V3.1 Backup Defaults: HMAC-SHA512 with input as key and
/// the default backup header as message.
pub struct QubesV31;

const QUBES_DEFAULT_BACKUP_HEADER: &[u8] =
    b"version=3\nhmac-algorithm=SHA512\ncrypto-algorithm=aes-256-cbc\nencrypted=True\ncompressed=False\n";

impl HashAlgorithm for QubesV31 {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        type HmacSha512 = Hmac<sha2::Sha512>;
        let mut mac =
            HmacSha512::new_from_slice(input).expect("HMAC-SHA512 accepts keys of any length");
        mac.update(QUBES_DEFAULT_BACKUP_HEADER);
        Some(mac.finalize().into_bytes().to_vec())
    }

    fn name(&self) -> &str {
        "QubesV3.1BackupDefaults"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors verified against PHP: md5(md5($s))

    #[test]
    fn test_md5md5_empty() {
        let hash = Md5Md5.hash(b"").expect("should not fail");
        assert_eq!(hex::encode(&hash), "74be16979710d4c4e7c6647856088456");
    }

    #[test]
    fn test_md5md5_hello() {
        let hash = Md5Md5.hash(b"hello").expect("should not fail");
        assert_eq!(hex::encode(&hash), "69a329523ce1ec88bf63061863d9cb14");
    }

    #[test]
    fn test_md5md5_emoji() {
        let hash = Md5Md5.hash("😀".as_bytes()).expect("should not fail");
        assert_eq!(hex::encode(&hash), "2fc864a682f0eb486908aaeacba17611");
    }

    #[test]
    fn test_md5md5_password() {
        let hash = Md5Md5.hash(b"password").expect("should not fail");
        assert_eq!(hex::encode(&hash), "696d29e0940a4957748fe3fc9efd22a3");
    }

    // Test vectors verified against PHP: sha1(sha1($s, true))

    #[test]
    fn test_mysql41_empty() {
        let hash = MySql41.hash(b"").expect("should not fail");
        assert_eq!(
            hex::encode(&hash),
            "be1bdec0aa74b4dcb079943e70528096cca985f8"
        );
    }

    #[test]
    fn test_mysql41_hello() {
        let hash = MySql41.hash(b"hello").expect("should not fail");
        assert_eq!(
            hex::encode(&hash),
            "6b4f89a54e2d27ecd7e8da05b4ab8fd9d1d8b119"
        );
    }

    #[test]
    fn test_mysql41_emoji() {
        let hash = MySql41.hash("😀".as_bytes()).expect("should not fail");
        assert_eq!(
            hex::encode(&hash),
            "b55edf8cd9ee23bfc3684ca55dcfb5774d18bb51"
        );
    }

    #[test]
    fn test_mysql41_password() {
        let hash = MySql41.hash(b"password").expect("should not fail");
        // MySQL PASSWORD() output (without the leading *)
        assert_eq!(
            hex::encode(&hash),
            "2470c0c06dee42fd1618bb99005adca2ec9d1e19"
        );
    }

    // QubesV31 - HMAC-SHA512 keyed by the input, over the fixed backup header.
    //
    // Vectors generated from the reference implementation this port must match:
    // `QubesV31BackupDefaultsHashAlgorithm` in crackstation-hashdb's MoreHashes.php,
    // called through `MoreHashAlgorithms::GetHashFunction("QubesV3.1BackupDefaults")`
    // under PHP 8.4.23, so they exercise the actual class rather than a re-derivation of
    // what it is believed to do. All eight matched this implementation on first run.
    //
    // The previous tests here asserted only that the output was 64 bytes and that it was
    // deterministic. Both hold for HMAC-SHA512 with the key and message swapped, with a
    // different header, or with no header at all -- so nothing pinned the definition.

    /// Hash of `input` as hex, for comparing against the PHP-generated vectors.
    fn qubes_hex(input: &[u8]) -> String {
        QubesV31
            .hash(input)
            .expect("QubesV31 accepts any input")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[test]
    fn test_qubesv31_matches_php_vectors() {
        for (input, expected) in [
            (&b""[..], "e049735b1fd0688a3ae35dcb5ef2e5509acb439e37b245a84feae77d6d0a53b7db67e4241d8e9624fb9ace305ffd4a3af28cd121ea5e6d90142bb6e9720bdb51"),
            (&b"password"[..], "312f11f044cc9a14dd74929c3e0851d8e3e46e59045056315526f20cb1389e8412ee1060607e283b20606fe20a254c58aded00f1492cb3faf38c53d45c9d487e"),
            (&b"a"[..], "76a522ef158fdefa0b66568b1133e31946f832db291c2173b2be29cf578f0dfeed1fd3124c27764d62b79b91cbb8df91715eef90c65798b4598b41c3014252f4"),
            ("p\u{e4}ssw\u{f6}rd".as_bytes(), "6b099ca9450a0a0f11471244d3cd22c51bdcd3ed294729df244a896a7347a3b6fff2d9e312d58e41c443256f9d4763222bae0fc37fcd858158b9c98e3592520a"),
            (&b"line1\nline2\n"[..], "498f146d10077d85760da7dc15db83873f8d1592e438b880555e4bec6a6e850eca3cb2e247953bd708aafc7227d20ec8bf917c982a1365c34287219edaa7e759"),
        ] {
            assert_eq!(qubes_hex(input), expected, "input {input:?}");
        }
    }

    /// Not valid UTF-8. The wordlist genuinely contains such words, and HMAC keys are
    /// byte strings, so this must hash rather than fail or be re-encoded.
    #[test]
    fn test_qubesv31_matches_php_on_non_utf8_input() {
        assert_eq!(
            qubes_hex(b"\xff\xfe\x00binary"),
            "e4ab4d2f4f75cdb1b7c304699cfea2f841318768a1bcf7c6ed72556f307acc5af3ea0dfe4d9d5a92df83e3bfad9eae1008264caadfe519667746409e4686e271"
        );
    }

    /// HMAC uses a key shorter than the block directly and hashes a longer one first, so
    /// SHA-512's 128-byte block is where an implementation diverges if it gets that wrong.
    #[test]
    fn test_qubesv31_matches_php_around_the_block_boundary() {
        assert_eq!(
            qubes_hex(&[b'K'; 128]),
            "a9794c0f1529502ab4674d29125acee6aa1ff039f67b558f137a30eb8a1a01febb5c478a17cb0ecf4f16e192939c731a487ce8736b0183dbff8b442e697e98b4"
        );
        assert_eq!(
            qubes_hex(&[b'K'; 129]),
            "12b4c43588346af9db5fae4739c39cfb9d1ad6e1a6062f750c3a2af467e63f6c4ba24769f25fa753bb752f7d0fb12b40a02d14aaa68eb43de59ffd1dd99a5396"
        );
    }

    /// The definition is "input is the key, header is the message". Swapping them also
    /// yields 64 deterministic bytes, which is why the old tests could not tell the
    /// difference -- so assert directly that the two differ.
    #[test]
    fn test_qubesv31_does_not_have_key_and_message_swapped() {
        type HmacSha512 = Hmac<sha2::Sha512>;
        let mut swapped = HmacSha512::new_from_slice(QUBES_DEFAULT_BACKUP_HEADER)
            .expect("HMAC-SHA512 accepts keys of any length");
        swapped.update(b"password");

        assert_ne!(
            QubesV31.hash(b"password").expect("hash"),
            swapped.finalize().into_bytes().to_vec(),
            "input keys the HMAC and the header is the message, not the reverse"
        );
    }

    /// The header is part of the definition: a Qubes backup with different settings has a
    /// different header and must hash differently.
    #[test]
    fn test_qubesv31_header_is_load_bearing() {
        type HmacSha512 = Hmac<sha2::Sha512>;
        let mut altered = HmacSha512::new_from_slice(b"password")
            .expect("HMAC-SHA512 accepts keys of any length");
        altered.update(b"version=3\nhmac-algorithm=SHA512\ncrypto-algorithm=aes-256-cbc\nencrypted=True\ncompressed=True\n");

        assert_ne!(
            QubesV31.hash(b"password").expect("hash"),
            altered.finalize().into_bytes().to_vec(),
            "changing one field of the backup header must change the digest"
        );
    }

    #[test]
    fn test_qubesv31_produces_64_bytes() {
        let hash = QubesV31.hash(b"password").expect("should not fail");
        assert_eq!(hash.len(), 64);
    }
}
