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

    // QubesV31 - HMAC-SHA512 with specific backup header (no external reference)

    #[test]
    fn test_qubesv31_produces_64_bytes() {
        let hash = QubesV31.hash(b"password").expect("should not fail");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_qubesv31_deterministic() {
        let h1 = QubesV31.hash(b"test").expect("should not fail");
        let h2 = QubesV31.hash(b"test").expect("should not fail");
        assert_eq!(h1, h2);
    }
}
