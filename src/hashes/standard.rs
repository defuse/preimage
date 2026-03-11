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

standard_hash!(Md2, "md2", md2::Md2);
standard_hash!(Md4, "md4", md4::Md4);
standard_hash!(Md5, "md5", md5::Md5);
standard_hash!(Sha1, "sha1", sha1::Sha1);
standard_hash!(Sha224, "sha224", sha2::Sha224);
standard_hash!(Sha256, "sha256", sha2::Sha256);
standard_hash!(Sha384, "sha384", sha2::Sha384);
standard_hash!(Sha512, "sha512", sha2::Sha512);
standard_hash!(Sha512_224, "sha512/224", sha2::Sha512_224);
standard_hash!(Sha512_256, "sha512/256", sha2::Sha512_256);
standard_hash!(Sha3_224, "sha3-224", sha3::Sha3_224);
standard_hash!(Sha3_256, "sha3-256", sha3::Sha3_256);
standard_hash!(Sha3_384, "sha3-384", sha3::Sha3_384);
standard_hash!(Sha3_512, "sha3-512", sha3::Sha3_512);
standard_hash!(Whirlpool, "whirlpool", whirlpool::Whirlpool);
standard_hash!(Ripemd128, "ripemd128", ripemd::Ripemd128);
standard_hash!(Ripemd160, "ripemd160", ripemd::Ripemd160);
standard_hash!(Ripemd256, "ripemd256", ripemd::Ripemd256);
standard_hash!(Ripemd320, "ripemd320", ripemd::Ripemd320);
standard_hash!(Gost94Test, "gost", gost94::Gost94Test);
standard_hash!(Gost94CryptoPro, "gost-crypto", gost94::Gost94CryptoPro);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md2() {
        let hash = Md2.hash(b"").expect("md2 should not fail");
        assert_eq!(hex::encode(&hash), "8350e5a3e24c153df2275c9f80692773");
    }

    #[test]
    fn test_md2_hello() {
        let hash = Md2.hash(b"hello").expect("md2 should not fail");
        assert_eq!(hex::encode(&hash), "a9046c73e00331af68917d3804f70655");
    }

    #[test]
    fn test_md4() {
        let hash = Md4.hash(b"").expect("md4 should not fail");
        assert_eq!(hex::encode(&hash), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn test_md4_hello() {
        let hash = Md4.hash(b"hello").expect("md4 should not fail");
        assert_eq!(hex::encode(&hash), "866437cb7a794bce2b727acc0362ee27");
    }

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

    #[test]
    fn test_sha512_224() {
        let hash = Sha512_224.hash(b"hello").expect("sha512/224 should not fail");
        assert_eq!(
            hex::encode(&hash),
            "fe8509ed1fb7dcefc27e6ac1a80eddbec4cb3d2c6fe565244374061c"
        );
    }

    #[test]
    fn test_sha512_256() {
        let hash = Sha512_256.hash(b"hello").expect("sha512/256 should not fail");
        assert_eq!(
            hex::encode(&hash),
            "e30d87cfa2a75db545eac4d61baf970366a8357c7f72fa95b52d0accb698f13a"
        );
    }

    #[test]
    fn test_sha3_256() {
        let hash = Sha3_256.hash(b"hello").expect("sha3-256 should not fail");
        assert_eq!(
            hex::encode(&hash),
            "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392"
        );
    }

    #[test]
    fn test_ripemd128() {
        let hash = Ripemd128.hash(b"hello").expect("ripemd128 should not fail");
        assert_eq!(hex::encode(&hash), "789d569f08ed7055e94b4289a4195012");
    }

    #[test]
    fn test_ripemd256() {
        let hash = Ripemd256.hash(b"hello").expect("ripemd256 should not fail");
        assert_eq!(
            hex::encode(&hash),
            "cc1d2594aece0a064b7aed75a57283d9490fd5705ed3d66bf9adfe3a58b25de5"
        );
    }

    #[test]
    fn test_ripemd320() {
        let hash = Ripemd320.hash(b"hello").expect("ripemd320 should not fail");
        assert_eq!(
            hex::encode(&hash),
            "eb0cf45114c56a8421fbcb33430fa22e0cd607560a88bbe14ce70bdf59bf55b11a3906987c487992"
        );
    }

    #[test]
    fn test_gost94() {
        let hash = Gost94Test.hash(b"hello").expect("gost should not fail");
        assert_eq!(
            hex::encode(&hash),
            "a7eb5d08ddf2363f1ea0317a803fcef81d33863c8b2f9f6d7d14951d229f4567"
        );
    }

    #[test]
    fn test_gost94_crypto() {
        let hash = Gost94CryptoPro.hash(b"hello").expect("gost-crypto should not fail");
        assert_eq!(
            hex::encode(&hash),
            "92ea6ddbaf40020df3651f278fd7151217a24aa8d22ebd2519cfd4d89e6450ea"
        );
    }
}
