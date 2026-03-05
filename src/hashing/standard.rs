use digest::Digest;
use super::HashAlgorithm;

macro_rules! standard_hash {
    ($rust_name:ident, $php_name:expr, $hasher:ty) => {
        pub struct $rust_name;

        impl HashAlgorithm for $rust_name {
            fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
                let mut hasher = <$hasher>::new();
                hasher.update(input);
                Some(hasher.finalize().to_vec())
            }

            fn name(&self) -> &str {
                $php_name
            }
        }
    };
}

standard_hash!(Md5, "md5", md5::Md5);
standard_hash!(Sha1, "sha1", sha1::Sha1);
standard_hash!(Sha224, "sha224", sha2::Sha224);
standard_hash!(Sha256, "sha256", sha2::Sha256);
standard_hash!(Sha384, "sha384", sha2::Sha384);
standard_hash!(Sha512, "sha512", sha2::Sha512);
standard_hash!(Whirlpool, "whirlpool", whirlpool::Whirlpool);
standard_hash!(Ripemd160, "ripemd160", ripemd::Ripemd160);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5() {
        let hash = Md5.hash(b"hello").expect("md5 should not fail");
        assert_eq!(hex::encode(&hash), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_md5_empty() {
        let hash = Md5.hash(b"").expect("md5 should not fail");
        assert_eq!(hex::encode(&hash), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_sha1() {
        let hash = Sha1.hash(b"hello").expect("sha1 should not fail");
        assert_eq!(hex::encode(&hash), "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
    }

    #[test]
    fn test_sha256() {
        let hash = Sha256.hash(b"hello").expect("sha256 should not fail");
        assert_eq!(
            hex::encode(&hash),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha512() {
        let hash = Sha512.hash(b"hello").expect("sha512 should not fail");
        assert_eq!(
            hex::encode(&hash),
            "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
        );
    }

    #[test]
    fn test_whirlpool() {
        // Known test vector: whirlpool("")
        let hash = Whirlpool.hash(b"").expect("whirlpool should not fail");
        assert_eq!(hash.len(), 64); // 512 bits
        assert_eq!(
            hex::encode(&hash),
            "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3"
        );
    }

    #[test]
    fn test_ripemd160() {
        let hash = Ripemd160.hash(b"hello").expect("ripemd160 should not fail");
        assert_eq!(hex::encode(&hash), "108f07b8382412612c048d07d13f814118445acd");
    }

    #[test]
    fn test_sha224() {
        let hash = Sha224.hash(b"hello").expect("sha224 should not fail");
        assert_eq!(
            hex::encode(&hash),
            "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193"
        );
    }

    #[test]
    fn test_sha384() {
        let hash = Sha384.hash(b"hello").expect("sha384 should not fail");
        assert_eq!(
            hex::encode(&hash),
            "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f"
        );
    }
}
