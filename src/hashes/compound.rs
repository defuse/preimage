use digest::Digest;
use hmac::{Hmac, Mac};
use super::HashAlgorithm;

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
        hasher.update(&first);
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
        let mut mac = HmacSha512::new_from_slice(input)
            .expect("HMAC-SHA512 accepts keys of any length");
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

    #[test]
    fn test_md5md5_password() {
        // MD5("password") = "5f4dcc3b5aa765d61d8327deb882cf99"
        // MD5("5f4dcc3b5aa765d61d8327deb882cf99") = "696d29e0940a4957748fe3fc9efd22a3"
        let hash = Md5Md5.hash(b"password").expect("should not fail");
        assert_eq!(hex::encode(&hash), "696d29e0940a4957748fe3fc9efd22a3");
    }

    #[test]
    fn test_mysql41_password() {
        // SHA1("password") = 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
        // SHA1(binary of above) = ...
        let hash = MySql41.hash(b"password").expect("should not fail");
        assert_eq!(hash.len(), 20);
        // Verify against known MySQL PASSWORD() output (without the leading *)
        assert_eq!(
            hex::encode(&hash),
            "2470c0c06dee42fd1618bb99005adca2ec9d1e19"
        );
    }

    #[test]
    fn test_qubesv31_produces_64_bytes() {
        // HMAC-SHA512 produces 64 bytes
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
