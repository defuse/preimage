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

```text
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
```text

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

```rust,no_run
use preimage::{HashResult, PreimageOracle, MD5, SHA1};
use std::path::Path;

# fn main() -> anyhow::Result<()> {
let mut oracle = PreimageOracle::new();
oracle.register("md5", MD5, Path::new("md5.idx"), Path::new("wordlist.txt"))?;
oracle.register("sha1", SHA1, Path::new("sha1.idx"), Path::new("wordlist.txt"))?;

for result in oracle.crack(&["5f4dcc3b5aa765d61d8327deb882cf99"], false)? {
    match result {
        HashResult::Lookup { queried_hash, matches, .. } => {
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
# Ok(())
# }
```

Invalid input is a variant, not an error: `crack` returns `InvalidFormat` for
non-hex, odd-length, or too-short input, and reserves `Err` for genuine I/O
failures. A hash that is well-formed but absent comes back as `Lookup` with an
empty `matches`.

You can index and crack with your own algorithm by implementing one trait:

```rust,no_run
use preimage::{HashAlgorithm, IndexFile, PreimageOracle};
use std::path::Path;

/// A toy algorithm, to keep the example self-contained: a real one would call
/// into a hash crate here and return the digest bytes.
struct MyHash;

impl HashAlgorithm for MyHash {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        let mut digest = [0u8; 8];
        for (slot, byte) in digest.iter_mut().zip(input) {
            *slot = *byte;
        }
        Some(digest.to_vec())
    }

    fn name(&self) -> &str {
        "my-hash"
    }
}

# fn main() -> anyhow::Result<()> {
let wordlist = Path::new("wordlist.txt");
let index_path = Path::new("my-hash.idx");
let mut oracle = PreimageOracle::new();

// Building takes any reference...
IndexFile::build(&MyHash, wordlist, index_path, None)?;

// ...while looking up stores the algorithm, so it wants a 'static one.
static MY_HASH: &dyn HashAlgorithm = &MyHash;
oracle.register("my-hash", MY_HASH, index_path, wordlist)?;
# Ok(())
# }
```

A custom algorithm does not join any registry: `preimage list` and the `-a` flag
resolve names through `allthehashes::get_algorithm`, which knows the built-ins
only. Your type works through the library, not the CLI.

Returning `None` marks input this algorithm cannot represent — that is how LM and
NTLM skip words outside their encodings, and those words are then absent from the
index rather than silently indexed as empty.

## Trust

The index and dictionary files must be **trusted**, and must not change while a
`LookupTable` holds them open. `preimage` searches data you built and own; it is not
hardened against a hostile index or wordlist.

A corrupt, truncated, unsorted or mismatched pair can make it return confidently wrong
answers, or terminate the process — an unsorted index defeats the binary search, and a
dictionary with no line terminator makes a lookup allocate until the allocator gives up.
Sortedness is not checked at open, deliberately: a production index is hundreds of
gigabytes and verifying it would mean reading all of it. `preimage check` does that when
you want it.

What malformed files cannot do is read out of bounds. The entry count comes from the
file's own length and every access is a bounds-checked slice, so a bad index panics
rather than reading past the mapping.

Note this is a claim about *files*. The robustness claim below — that invalid input is a
variant rather than an error — is about the **query string**, and does not extend to the
files.

## Compatibility

`preimage` reads indexes built by the original `createidx.php`. The test suite cracks
hashes against committed PHP-generated fixtures for md5, sha1 and NTLM, and checks a
PHP-sorted index with `preimage`'s own checker, rather than trusting the format
description.

The other direction — the original `checksort` accepting an index `preimage` wrote — is
not tested here, because that tool is not part of this repository.

## Development

```bash
cargo test                 # the two libraries
cargo test --all-features  # everything, including the CLI and benchmark binaries
```

Both binaries are behind features — `preimage` behind `cli`, `benchmark` behind
`bench` — so a plain `cargo test` does not compile them and silently skips their
tests. Use `--all-features` to run the whole suite.

Sorting is covered at the buffer-capacity boundaries — exactly at capacity, one
under, one over, and multiples of it — plus already-sorted, reverse-sorted and
all-identical inputs. Every case runs at three memory budgets, so each one is
sorted both entirely in memory and entirely through the file-based quicksort,
and the two are required to produce byte-identical files.

Note that sorted and reverse-sorted input is not the adversarial case for *this*
sorter: with a middle-element pivot they are its best case. The input that
degenerates it is one where every key compares equal.

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
