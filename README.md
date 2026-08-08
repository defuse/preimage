# preimage

Hash lookup tables for password cracking. Given a wordlist, `preimage` builds a
sorted index that maps hash prefixes back to positions in that wordlist, so
recovering the plaintext behind a hash is a binary search and a seek instead of a
scan.

This repository holds two crates:

| Crate | What it is |
| --- | --- |
| [`preimage`](preimage/) | Index building, sorting, and lookup, plus the `preimage` CLI |
| [`allthehashes`](allthehashes/) | 58 hash algorithms behind one `HashAlgorithm` trait |

It is a Rust port of [crackstation-hashdb](https://github.com/defuse/crackstation-hashdb),
the PHP/C code behind [crackstation.net](https://crackstation.net/), and it reads and
writes the same on-disk index format.

## How it works

A wordlist is arbitrary bytes separated by `\n`. For each word, `preimage` records a
14-byte index entry:

```
+---------------------------+-------------------+
| first 8 bytes of the hash | 6-byte position   |
+---------------------------+-------------------+
```

The index is then sorted by hash prefix. To look a hash up, binary search the index
for its first 8 bytes, seek to each matching position in the wordlist, and read the
word. Because only a prefix is stored, a hit is a *candidate*: the word is re-hashed
to confirm it. That re-hash is also what distinguishes a full match from a prefix
match when you only have a truncated hash.

Storing a prefix rather than the whole digest is what keeps the index small and the
format algorithm-independent — a 14-byte entry costs the same whether it indexes MD5
or SHA-512.

The cost is one binary search over an mmap'd file. CrackStation's real wordlist is
about 1.2 billion words, which is roughly a 17 GB index and about 31 seeks per
lookup.

## Install

```bash
cargo install preimage          # the CLI
cargo add preimage              # the library
```

The library pulls in `clap` and friends only for the CLI; depend on it with
`default-features = false` to skip them:

```toml
preimage = { version = "0.1", default-features = false }
```

## Command line

```bash
# 1. Create an unsorted index from a wordlist
preimage create -a md5 -w wordlist.txt -o md5.idx

# 2. Sort it in place — DO NOT INTERRUPT, a partial sort corrupts the file
preimage sort md5.idx                 # 2 GiB buffer by default
preimage sort --memory 4G md5.idx     # bigger buffer, fewer passes
preimage sort --ram md5.idx           # all in RAM, errors if it doesn't fit

# 3. Confirm it is sorted
preimage check md5.idx

# 4. Look hashes up
preimage lookup -a md5 -i md5.idx -d wordlist.txt 5f4dcc3b5aa765d61d8327deb882cf99

# 5. See the supported algorithms
preimage list
```

Sorting is deterministic: the same wordlist always produces a byte-identical index.

To search several tables at once, describe them in a config file and use
`preimage lookup --config tables.toml <hash>...`:

```toml
[[table]]
label = "md5-small"
algorithm = "md5"
index = "/data/md5-small.idx"
dictionary = "/data/small.txt"

[[table]]
label = "sha1-small"
algorithm = "sha1"
index = "/data/sha1-small.idx"
dictionary = "/data/small.txt"
```

## Library

`PreimageOracle` is the multi-table entry point. Registration order is match order.

```rust
use preimage::{HashResult, PreimageOracle, MD5, SHA1};
use std::path::Path;

let mut oracle = PreimageOracle::new();
oracle.register("md5", MD5, Path::new("md5.idx"), Path::new("wordlist.txt"))?;
oracle.register("sha1", SHA1, Path::new("sha1.idx"), Path::new("wordlist.txt"))?;

for result in oracle.crack(&["5f4dcc3b5aa765d61d8327deb882cf99"], false)? {
    match result {
        HashResult::Lookup { queried_hash, matches } => {
            for m in matches {
                println!(
                    "{} = {:?} via {} ({}, full match: {})",
                    queried_hash,
                    m.lookup_match.plaintext_lossy(),
                    m.table_label,
                    m.lookup_match.algorithm().name(),
                    m.lookup_match.is_full(),
                );
            }
        }
        HashResult::InvalidFormat { input } => {
            println!("{input} is not a valid hash");
        }
    }
}
```

Invalid input is a variant, not an error: `crack` returns `InvalidFormat` for
non-hex, odd-length, or too-short input, and reserves `Err` for genuine I/O
failures. A hash that is well-formed but absent comes back as `Lookup` with an
empty `matches`.

Adding an algorithm means implementing one trait:

```rust
use preimage::HashAlgorithm;

struct MyHash;

impl HashAlgorithm for MyHash {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        Some(/* digest bytes */)
    }
    fn name(&self) -> &str { "my-hash" }
}
```

Returning `None` marks input this algorithm cannot represent — that is how LM and
NTLM skip words outside their encodings, and those words are then absent from the
index rather than silently indexed as empty.

## Compatibility

Indexes are byte-compatible with the original PHP/C implementation in both
directions: `preimage` cracks hashes using indexes built by `createidx.php`, and its
own output passes the original `checksort`. The test suite checks this against
committed PHP-generated fixtures rather than trusting the format description.

## Development

```bash
cargo test --workspace
```

Sorting is covered at the boundaries that historically break external sorts —
exactly at buffer capacity, one under, one over, and multiples of it, plus
already-sorted, reverse-sorted, and all-identical inputs.

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
have. Until then, weigh that against whatever you are considering using it for — a
passing test suite is not the same as a read-through by someone who understands the
consequences of getting this wrong.

If you would like to submit a PR, using AI is fine, but you must stand by the
correctness of your submission as strongly as you would if you had written the code
yourself.
