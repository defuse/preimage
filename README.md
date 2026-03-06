# preimage

A hash lookup table toolkit. Creates, sorts, and queries precomputed hash
indexes for fast plaintext recovery. Rust port of
[crackstation-hashdb](https://github.com/defuse/crackstation-hashdb).

## How it works

Given a wordlist (a file of plaintexts separated by `\n`), preimage builds a
sorted index that maps hash prefixes back to their position in the wordlist.
Looking up a hash is a binary search over the index followed by a seek into the
wordlist to read the plaintext.

### Index format

Each index entry is 14 bytes:

```
[8 bytes: hash prefix][6 bytes: little-endian wordlist byte offset]
```

The 8-byte prefix is the first 8 bytes of the hash digest. The 6-byte offset
points to the start of the corresponding line in the wordlist file (max 256 TiB).

### Lookup

1. Parse the hex-encoded query hash
2. Binary search the sorted index for the 8-byte prefix
3. Walk the collision block (all entries sharing the same prefix)
4. For each match, seek to the wordlist offset, read the word, recompute the
   full hash, and compare against the query
5. Return full matches (entire hash matches) and partial matches (only prefix
   matched)

### Example sizes

| Wordlist entries | Index size | Binary search steps |
|------------------|------------|---------------------|
| 1,000,000        | 13 MiB     | 20                  |
| 100,000,000      | 1.3 GiB    | 27                  |
| 1,000,000,000    | 13.0 GiB   | 30                  |

A 1-billion-word dictionary produces a 13 GiB index per algorithm. Lookups
touch at most 30 index entries (binary search) plus one wordlist seek per
candidate in the collision block.

## Supported algorithms

md5, sha1, sha224, sha256, sha384, sha512, whirlpool, ripemd160, LM, NTLM,
md5(md5), MySQL4.1+, QubesV3.1BackupDefaults

## Usage

### Build an index

```
preimage create md5 wordlist.txt md5.idx
```

This reads every line from `wordlist.txt`, hashes it with MD5, and writes a
14-byte entry to `md5.idx`. The index is unsorted at this point.

### Sort the index

```
preimage sort md5.idx
preimage sort --ram md5.idx            # load entirely into RAM
preimage sort --memory 4096 md5.idx    # use a 4 GiB buffer
```

Sorts the index in-place. The default mode uses a 256 MiB buffer and falls back
to on-disk quicksort for partitions that don't fit. `--ram` loads the entire
file into memory (faster, needs enough RAM).

**Warning:** Do not interrupt sorting (e.g. Ctrl+C). The index file will be
corrupted and must be regenerated.

### Verify sort order

```
preimage check md5.idx
```

Exits 0 if sorted, 1 if not.

### Look up hashes

Single-table lookup:

```
preimage lookup -a md5 -i md5.idx -d wordlist.txt 5d41402abc4b2a76b9719d911017c592
```

Multi-table lookup via config file:

```
preimage lookup --config tables.toml 5d41402abc4b2a76b9719d911017c592
```

Config file format (`tables.toml`):

```toml
[[table]]
label = "md5-small"
algorithm = "md5"
index = "/path/to/md5-small.idx"
dictionary = "/path/to/small.txt"

[[table]]
label = "sha1-large"
algorithm = "sha1"
index = "/path/to/sha1-large.idx"
dictionary = "/path/to/large.txt"
```

### List algorithms

```
preimage algorithms
```

## Cargo features

| Feature | Default | Description |
|---------|---------|-------------|
| `cli` | yes | Builds the `preimage` CLI binary. Adds `clap`, `toml`, `serde`. |
| `bench` | no | Builds the `benchmark` binary. Adds `rand`, `humansize`. |

Use `default-features = false` when depending on preimage as a library to avoid
pulling in CLI dependencies:

```toml
[dependencies]
preimage = { path = "../preimage", default-features = false }
```

## Library usage

```rust
use preimage::hashing::Md5;
use preimage::lookup::LookupTable;
use preimage::oracle::PreimageOracle;

// Single-table lookup
let table = LookupTable::open(Md5, "md5.idx", "wordlist.txt")?;
let matches = table.lookup("5d41402abc4b2a76b9719d911017c592")?;

// Multi-table lookup
let mut oracle = PreimageOracle::new();
oracle.register("md5", Md5, "md5.idx", "wordlist.txt")?;
let results = oracle.crack(&["5d41402abc4b2a76b9719d911017c592"], false);
```

Custom hash algorithms can be added by implementing the `HashAlgorithm` trait:

```rust
use preimage::hashing::HashAlgorithm;

struct MyHash;

impl HashAlgorithm for MyHash {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        // compute hash, return None if input is invalid for this algorithm
        Some(vec![/* hash bytes */])
    }
    fn name(&self) -> &str { "my-hash" }
}
```

## Benchmarking

The `benchmark` binary measures wordlist generation, index build, sort, and
lookup throughput for synthetic wordlists of any size.

```
cargo run --release --features bench --bin benchmark -- --entries 1M --duration 10
```

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--entries <N>` | required | Wordlist size (`K`/`M`/`G` suffixes) |
| `-a, --algorithm` | `md5` | Hash algorithm |
| `-p, --parallel` | `1` | Lookup threads |
| `-b, --batch` | `1000` | Queries per batch (for latency stats) |
| `-d, --duration` | `10` | Seconds to run lookups |
| `-m, --memory` | `2G` | Sort buffer size |
| `--data-dir` | `benchmark_data` | Directory for generated files |
| `--clean` | off | Delete existing files before run |

Generated wordlists and indexes are cached in `--data-dir` and reused across
runs unless `--clean` is passed.

### Profiling with flamegraph

Install [cargo-flamegraph](https://github.com/flamegraphs/flamegraph):

```
cargo install flamegraph
```

On Linux, allow perf events for non-root users (resets on reboot):

```
echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid
```

Generate a flamegraph (outputs `flamegraph.svg`):

```
cargo flamegraph --release --features bench --bin benchmark -- --entries 100M --duration 10 --clean
```

Open `flamegraph.svg` in a browser — it's interactive (click to zoom into call
stacks).
