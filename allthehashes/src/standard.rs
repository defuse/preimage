use digest::Digest;
use crate::HashAlgorithm;

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

    // Test vectors verified against PHP's hash() function (defuse.ca/checksums.htm)

    // MD2
    #[test]
    fn test_md2_empty() {
        assert_eq!(hex::encode(Md2.hash(b"").unwrap()), "8350e5a3e24c153df2275c9f80692773");
    }
    #[test]
    fn test_md2_hello() {
        assert_eq!(hex::encode(Md2.hash(b"hello").unwrap()), "a9046c73e00331af68917d3804f70655");
    }
    #[test]
    fn test_md2_emoji() {
        assert_eq!(hex::encode(Md2.hash("😀".as_bytes()).unwrap()), "d2d4e9ddd66e9ce4ee288aea24a345de");
    }

    // MD4
    #[test]
    fn test_md4_empty() {
        assert_eq!(hex::encode(Md4.hash(b"").unwrap()), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }
    #[test]
    fn test_md4_hello() {
        assert_eq!(hex::encode(Md4.hash(b"hello").unwrap()), "866437cb7a794bce2b727acc0362ee27");
    }
    #[test]
    fn test_md4_emoji() {
        assert_eq!(hex::encode(Md4.hash("😀".as_bytes()).unwrap()), "d60c87f11ac824ea903b6d937e840081");
    }

    // MD5
    #[test]
    fn test_md5_empty() {
        assert_eq!(hex::encode(Md5.hash(b"").unwrap()), "d41d8cd98f00b204e9800998ecf8427e");
    }
    #[test]
    fn test_md5_hello() {
        assert_eq!(hex::encode(Md5.hash(b"hello").unwrap()), "5d41402abc4b2a76b9719d911017c592");
    }
    #[test]
    fn test_md5_emoji() {
        assert_eq!(hex::encode(Md5.hash("😀".as_bytes()).unwrap()), "2a02eac39d716a70ecf37579185927b6");
    }

    // SHA-1
    #[test]
    fn test_sha1_empty() {
        assert_eq!(hex::encode(Sha1.hash(b"").unwrap()), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }
    #[test]
    fn test_sha1_hello() {
        assert_eq!(hex::encode(Sha1.hash(b"hello").unwrap()), "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
    }
    #[test]
    fn test_sha1_emoji() {
        assert_eq!(hex::encode(Sha1.hash("😀".as_bytes()).unwrap()), "9c533688a979a858cbd6a43c9f91aba624651f18");
    }

    // SHA-224
    #[test]
    fn test_sha224_empty() {
        assert_eq!(hex::encode(Sha224.hash(b"").unwrap()), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    }
    #[test]
    fn test_sha224_hello() {
        assert_eq!(hex::encode(Sha224.hash(b"hello").unwrap()), "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193");
    }
    #[test]
    fn test_sha224_emoji() {
        assert_eq!(hex::encode(Sha224.hash("😀".as_bytes()).unwrap()), "0965afc5f46fff2c3761b506dac6c4dcfd118e72551dc60d39cb1c1c");
    }

    // SHA-256
    #[test]
    fn test_sha256_empty() {
        assert_eq!(hex::encode(Sha256.hash(b"").unwrap()), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
    #[test]
    fn test_sha256_hello() {
        assert_eq!(hex::encode(Sha256.hash(b"hello").unwrap()), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }
    #[test]
    fn test_sha256_emoji() {
        assert_eq!(hex::encode(Sha256.hash("😀".as_bytes()).unwrap()), "f0443a342c5ef54783a111b51ba56c938e474c32324d90c3a60c9c8e3a37e2d9");
    }

    // SHA-384
    #[test]
    fn test_sha384_empty() {
        assert_eq!(hex::encode(Sha384.hash(b"").unwrap()), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    }
    #[test]
    fn test_sha384_hello() {
        assert_eq!(hex::encode(Sha384.hash(b"hello").unwrap()), "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f");
    }
    #[test]
    fn test_sha384_emoji() {
        assert_eq!(hex::encode(Sha384.hash("😀".as_bytes()).unwrap()), "a97c579cff8389234376aa6ebefbc82c6ad6313b1373633fb1ae6f1d07a0e02c39c5e48d3a2f6971aa2f3c1bf1b5695b");
    }

    // SHA-512
    #[test]
    fn test_sha512_empty() {
        assert_eq!(hex::encode(Sha512.hash(b"").unwrap()), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }
    #[test]
    fn test_sha512_hello() {
        assert_eq!(hex::encode(Sha512.hash(b"hello").unwrap()), "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043");
    }
    #[test]
    fn test_sha512_emoji() {
        assert_eq!(hex::encode(Sha512.hash("😀".as_bytes()).unwrap()), "9b1ce8b6649e678e1cb7bca85afeaae750add5cfb0668d25ebba5e7f0038f1b6bdcc4bacd909049e752be2a3a3c0158c0f2bb5a33d8101b2ed5d74a66ece2425");
    }

    // SHA-512/224
    #[test]
    fn test_sha512_224_empty() {
        assert_eq!(hex::encode(Sha512_224.hash(b"").unwrap()), "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
    }
    #[test]
    fn test_sha512_224_hello() {
        assert_eq!(hex::encode(Sha512_224.hash(b"hello").unwrap()), "fe8509ed1fb7dcefc27e6ac1a80eddbec4cb3d2c6fe565244374061c");
    }
    #[test]
    fn test_sha512_224_emoji() {
        assert_eq!(hex::encode(Sha512_224.hash("😀".as_bytes()).unwrap()), "d29f43fcaaf30000275e2d752992c8761e0272e52c08a4bd79fd9ec5");
    }

    // SHA-512/256
    #[test]
    fn test_sha512_256_empty() {
        assert_eq!(hex::encode(Sha512_256.hash(b"").unwrap()), "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
    }
    #[test]
    fn test_sha512_256_hello() {
        assert_eq!(hex::encode(Sha512_256.hash(b"hello").unwrap()), "e30d87cfa2a75db545eac4d61baf970366a8357c7f72fa95b52d0accb698f13a");
    }
    #[test]
    fn test_sha512_256_emoji() {
        assert_eq!(hex::encode(Sha512_256.hash("😀".as_bytes()).unwrap()), "f2e2add15f6f5ede243087b6e15f4a5b146ef724b4c58c268750b6d0be1f993d");
    }

    // SHA3-224
    #[test]
    fn test_sha3_224_empty() {
        assert_eq!(hex::encode(Sha3_224.hash(b"").unwrap()), "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
    }
    #[test]
    fn test_sha3_224_hello() {
        assert_eq!(hex::encode(Sha3_224.hash(b"hello").unwrap()), "b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81");
    }
    #[test]
    fn test_sha3_224_emoji() {
        assert_eq!(hex::encode(Sha3_224.hash("😀".as_bytes()).unwrap()), "6f0d369cbc7b7947fd2d86f449358a76e4d688539d9257ecee8be29c");
    }

    // SHA3-256
    #[test]
    fn test_sha3_256_empty() {
        assert_eq!(hex::encode(Sha3_256.hash(b"").unwrap()), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    }
    #[test]
    fn test_sha3_256_hello() {
        assert_eq!(hex::encode(Sha3_256.hash(b"hello").unwrap()), "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392");
    }
    #[test]
    fn test_sha3_256_emoji() {
        assert_eq!(hex::encode(Sha3_256.hash("😀".as_bytes()).unwrap()), "0f2a376a2af79037549328fa8f76fc6c41b97ff3c10107d7297d0339e3380e3c");
    }

    // SHA3-384
    #[test]
    fn test_sha3_384_empty() {
        assert_eq!(hex::encode(Sha3_384.hash(b"").unwrap()), "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
    }
    #[test]
    fn test_sha3_384_hello() {
        assert_eq!(hex::encode(Sha3_384.hash(b"hello").unwrap()), "720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa1330ff07c0fddee54699a4c3ee0ee9d887");
    }
    #[test]
    fn test_sha3_384_emoji() {
        assert_eq!(hex::encode(Sha3_384.hash("😀".as_bytes()).unwrap()), "a489cee429064d38903ae94e3724e67c69d86decad8a2a761fcbfe8d193ff1b7a807429d5a8c45f79bae3833366ae5f9");
    }

    // SHA3-512
    #[test]
    fn test_sha3_512_empty() {
        assert_eq!(hex::encode(Sha3_512.hash(b"").unwrap()), "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    }
    #[test]
    fn test_sha3_512_hello() {
        assert_eq!(hex::encode(Sha3_512.hash(b"hello").unwrap()), "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976");
    }
    #[test]
    fn test_sha3_512_emoji() {
        assert_eq!(hex::encode(Sha3_512.hash("😀".as_bytes()).unwrap()), "961e8fa060f009c47a3e6b3f2676143fc04b653baf3f94825f631205f2620be63640735633c3e02382d1f4a9ae4d85215f120f299394b8c0e036c4137a2c7f7e");
    }

    // RIPEMD-128
    #[test]
    fn test_ripemd128_empty() {
        assert_eq!(hex::encode(Ripemd128.hash(b"").unwrap()), "cdf26213a150dc3ecb610f18f6b38b46");
    }
    #[test]
    fn test_ripemd128_hello() {
        assert_eq!(hex::encode(Ripemd128.hash(b"hello").unwrap()), "789d569f08ed7055e94b4289a4195012");
    }
    #[test]
    fn test_ripemd128_emoji() {
        assert_eq!(hex::encode(Ripemd128.hash("😀".as_bytes()).unwrap()), "394b80f545f4e77a8e6e300a826bced9");
    }

    // RIPEMD-160
    #[test]
    fn test_ripemd160_empty() {
        assert_eq!(hex::encode(Ripemd160.hash(b"").unwrap()), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    }
    #[test]
    fn test_ripemd160_hello() {
        assert_eq!(hex::encode(Ripemd160.hash(b"hello").unwrap()), "108f07b8382412612c048d07d13f814118445acd");
    }
    #[test]
    fn test_ripemd160_emoji() {
        assert_eq!(hex::encode(Ripemd160.hash("😀".as_bytes()).unwrap()), "22daaf01b6c6700c5069a76c9a8e4b3f3ec62fc2");
    }

    // RIPEMD-256
    #[test]
    fn test_ripemd256_empty() {
        assert_eq!(hex::encode(Ripemd256.hash(b"").unwrap()), "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d");
    }
    #[test]
    fn test_ripemd256_hello() {
        assert_eq!(hex::encode(Ripemd256.hash(b"hello").unwrap()), "cc1d2594aece0a064b7aed75a57283d9490fd5705ed3d66bf9adfe3a58b25de5");
    }
    #[test]
    fn test_ripemd256_emoji() {
        assert_eq!(hex::encode(Ripemd256.hash("😀".as_bytes()).unwrap()), "bfdf1e152e774c3dfab03692c79ed2b7590981be150e8f912ca7a118d2b722a9");
    }

    // RIPEMD-320
    #[test]
    fn test_ripemd320_empty() {
        assert_eq!(hex::encode(Ripemd320.hash(b"").unwrap()), "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8");
    }
    #[test]
    fn test_ripemd320_hello() {
        assert_eq!(hex::encode(Ripemd320.hash(b"hello").unwrap()), "eb0cf45114c56a8421fbcb33430fa22e0cd607560a88bbe14ce70bdf59bf55b11a3906987c487992");
    }
    #[test]
    fn test_ripemd320_emoji() {
        assert_eq!(hex::encode(Ripemd320.hash("😀".as_bytes()).unwrap()), "d9017c2c6c5fa63364037891884b75cc3224eb32f288e794acacfb910a2ac0d93909e1ff281bc378");
    }

    // Whirlpool
    #[test]
    fn test_whirlpool_empty() {
        assert_eq!(hex::encode(Whirlpool.hash(b"").unwrap()), "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3");
    }
    #[test]
    fn test_whirlpool_hello() {
        assert_eq!(hex::encode(Whirlpool.hash(b"hello").unwrap()), "0a25f55d7308eca6b9567a7ed3bd1b46327f0f1ffdc804dd8bb5af40e88d78b88df0d002a89e2fdbd5876c523f1b67bc44e9f87047598e7548298ea1c81cfd73");
    }
    #[test]
    fn test_whirlpool_emoji() {
        assert_eq!(hex::encode(Whirlpool.hash("😀".as_bytes()).unwrap()), "f6c76df71127b5fb60831e76e7cb943c7edc111d9363724210aa7a06e24e92c7e2cf2068635002612ccc0aca34f4fa219c61a10b79154d6ccf5572fac14980cc");
    }

    // GOST R 34.11-94 (test params)
    #[test]
    fn test_gost_empty() {
        assert_eq!(hex::encode(Gost94Test.hash(b"").unwrap()), "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d");
    }
    #[test]
    fn test_gost_hello() {
        assert_eq!(hex::encode(Gost94Test.hash(b"hello").unwrap()), "a7eb5d08ddf2363f1ea0317a803fcef81d33863c8b2f9f6d7d14951d229f4567");
    }
    #[test]
    fn test_gost_emoji() {
        assert_eq!(hex::encode(Gost94Test.hash("😀".as_bytes()).unwrap()), "131b2dacc0532144e11c423ce25128d626e0458be42dc2cd94f95423a836bbee");
    }

    // GOST R 34.11-94 (CryptoPro params)
    #[test]
    fn test_gost_crypto_empty() {
        assert_eq!(hex::encode(Gost94CryptoPro.hash(b"").unwrap()), "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0");
    }
    #[test]
    fn test_gost_crypto_hello() {
        assert_eq!(hex::encode(Gost94CryptoPro.hash(b"hello").unwrap()), "92ea6ddbaf40020df3651f278fd7151217a24aa8d22ebd2519cfd4d89e6450ea");
    }
    #[test]
    fn test_gost_crypto_emoji() {
        assert_eq!(hex::encode(Gost94CryptoPro.hash("😀".as_bytes()).unwrap()), "851e0b715e5a36c4fa6557541540c3893473857ee9f89803a614967aaca6896b");
    }
}
