# allthehashes

> **⚠️ Not for cryptographic use.** This crate deliberately includes insecure
> hash functions — MD5, SHA-1, LM, NTLM and the checksums are broken by design or
> by age — and none of the implementations here has had a security review. It is
> for password cracking and interoperability with old systems. Do not use it to
> protect anything.

Every hash function in one crate, behind a single trait.

`allthehashes` collects 58 hash and checksum algorithms — the set published on
[defuse.ca's checksums page](https://defuse.ca/checksums.htm) — and exposes each
one as a `&'static dyn HashAlgorithm`, so callers can select an algorithm at
runtime by name without knowing anything about the implementation behind it.

It exists to serve [`preimage`](https://crates.io/crates/preimage), which needs to
hash a wordlist under an algorithm chosen at runtime, but it has no dependency on
`preimage` and is useful on its own.

## The trait

```rust
pub trait HashAlgorithm: Send + Sync {
    /// Returns None if the input is invalid for this algorithm.
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>>;

    /// Human-readable name, matching PHP's naming exactly.
    fn name(&self) -> &str;
}
```

`hash` returns `Option` rather than always producing digest bytes because some
algorithms genuinely cannot represent some inputs: NTLM requires valid UTF-8, and
LM only covers a restricted character set. Returning `None` lets a caller skip
those inputs instead of silently indexing them as the hash of the empty string —
a real bug in the PHP code this crate descends from.

## Usage

Every algorithm is available as a static, and by name:

```rust
use allthehashes::{get_algorithm, HashAlgorithm, MD5, SHA256};

let digest = MD5.hash(b"hello").expect("md5 accepts any bytes");
assert_eq!(hex::encode(digest), "5d41402abc4b2a76b9719d911017c592");

// Runtime selection by name
let algorithm = get_algorithm("sha256").expect("sha256 exists");
assert_eq!(algorithm.name(), "sha256");
```

Adding your own is one impl:

```rust
use allthehashes::HashAlgorithm;

struct MyHash;

impl HashAlgorithm for MyHash {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        Some(/* digest bytes */)
    }
    fn name(&self) -> &str { "my-hash" }
}
```

## What's included

- **Common digests**: md2, md4, md5, sha1, sha224, sha256, sha384, sha512,
  sha512/224, sha512/256, sha3-224, sha3-256, sha3-384, sha3-512
- **Others**: ripemd128/160/256/320, whirlpool, snefru, snefru256, gost,
  gost-crypto, and the haval and tiger families in all their digest-size and
  pass-count variants
- **Checksums**: adler32, crc32, crc32b, crc32c, fnv132, fnv164, fnv1a32,
  fnv1a64, joaat
- **Password formats**: LM, NTLM, MySQL4.1+, `md5(md5)`, QubesV3.1BackupDefaults

Names are the identifiers `get_algorithm` accepts, and they match PHP's `hash()`
naming so indexes and scripts written against the PHP originals keep working.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual
licensed as above, without any additional terms or conditions.

## AI Use Policy

This software was written with heavy assistance from AI tools, and **has not yet
been reviewed by a human**. I intend to review it and will update this notice once I
have.

If you would like to submit a PR, using AI is fine, but you must stand by the
correctness of your submission as strongly as you would if you had written the code
yourself.
