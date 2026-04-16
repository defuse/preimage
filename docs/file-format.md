# Preimage Index File Format

This document describes the new headered index format and the compatibility rules for opening older no-header index files.

## Goals

- Preserve compatibility with existing no-header indexes.
- Make interrupted create and sort operations detectable.
- Store enough metadata to support future generalized index widths.
- Parse strictly and reject anything suspicious.
- Keep the format easy to parse.

## Endianness

All integer fields are little-endian.

## Headered Format

New indexes use a fixed-size 256-byte header. The header version determines the meaning of the header and its size.

For `header_version = 1`, the header is exactly 256 bytes.

```text
Preimage Index Header v1
Fixed size: 256 bytes
Byte order: little-endian for all integer fields

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-------------------------------+-------------------------------+
 |                                                               |
 +                        magic[16] (ASCII)                      +
 |                                                               |
 +-------------------------------+-------------------------------+
 |                     header_version (u32)                      |
 +-------------------------------+-------------------------------+
 |                         state (u32)                           |
 +-------------------------------+-------------------------------+
 |                                                               |
 +                                                               +
 |                                                               |
 +                                                               +
 |                                                               |
 +                  hash_name_ascii[128]                         +
 |                 ASCII, NUL-padded, no UTF-8                   +
 |                                                               |
 +                                                               +
 |                                                               |
 +                                                               +
 |                                                               |
 +-------------------------------+-------------------------------+
 |                    hash_prefix_bits (u32)                     |
 +-------------------------------+-------------------------------+
 |                dictionary_address_bits (u32)                  |
 +-------------------------------+-------------------------------+
 |                                                               |
 +                       entry_count (u64)                       +
 |                                                               |
 +-------------------------------+-------------------------------+
 |                                                               |
 +                                                               +
 |                                                               |
 +                       reserved[88]                            +
 |                       must be all zero                        +
 |                                                               |
 +                                                               +
 |                                                               |
 +-------------------------------+-------------------------------+
```

## Field Meanings

- `magic[16]`
  - ASCII format marker
  - proposed value: `PREIMAGE-IDX\0\0\0\0`

- `header_version`
  - `u32`
  - initial value: `1`

- `state`
  - `u32`
  - values:
    - `1 = Creating`
    - `2 = Created`
    - `3 = Sorting`
    - `4 = Sorted`

- `hash_name_ascii[128]`
  - ASCII algorithm name
  - NUL-padded
  - examples: `md5`, `sha256`, `NTLM`, `whirlpool`

- `hash_prefix_bits`
  - stored hash-prefix width in bits
  - future-oriented
  - v1 requires `64`

- `dictionary_address_bits`
  - stored dictionary-address width in bits
  - future-oriented
  - v1 requires `48`

- `entry_count`
  - redundant integrity check
  - payload size remains the physical source of truth

- `reserved[88]`
  - must be zero in v1

## Derived Entry Size

Entry size is not stored directly. It is derived from the bit widths:

```text
entry_size_bytes =
    ceil(hash_prefix_bits / 8) +
    ceil(dictionary_address_bits / 8)
```

For v1:

```text
entry_size_bytes = ceil(64 / 8) + ceil(48 / 8) = 8 + 6 = 14
```

## Source of Truth

The format follows a single-source-of-truth approach wherever possible.

- `hash_name_ascii` is the source of truth for the algorithm recorded in a headered file.
- `hash_prefix_bits` is the source of truth for stored hash-prefix width.
- `dictionary_address_bits` is the source of truth for dictionary-address width.
- Entry size is derived from those bit widths.
- File payload size is the source of truth for what physically exists on disk.
- `entry_count` is the intentional redundancy used to detect corruption or truncation.

For headered files:

```text
payload_size = file_size - 256
expected_payload_size = entry_count * entry_size_bytes
```

The parser must reject mismatches.

## State Semantics

For headered indexes:

- `Creating`
  - build started but did not finish
  - opening should fail

- `Created`
  - build finished
  - sort has not completed
  - lookup should fail

- `Sorting`
  - sort started but did not finish
  - opening should fail

- `Sorted`
  - safe for lookup

Lookup is allowed to trust the `Sorted` state bit rather than re-running a full structural sortedness scan.

## Algorithm Handling

The caller must always supply the algorithm name.

For headered indexes:

- the supplied algorithm is required
- the header hash name is used only as a strict sanity check
- mismatches must be rejected

For legacy no-header indexes:

- there is no embedded algorithm name
- the caller-supplied algorithm remains the only source of truth

This keeps the tool on one main API path while still validating headered indexes strictly.

## Strict Parsing Rules

Headered indexes must be rejected if any of the following are true:

- unknown header version
- unknown state value
- non-ASCII hash name
- unsupported hash name
- supplied algorithm does not exactly match the header hash name
- nonzero reserved bytes
- unsupported `hash_prefix_bits`
- unsupported `dictionary_address_bits`
- payload size is inconsistent with the derived entry size
- `entry_count` does not match payload size
- state is `Creating`
- state is `Sorting`
- state is `Created` when opening for lookup

The parser should reject on suspicion rather than attempting to continue.

## Legacy No-Header Support

Existing indexes without a header remain supported.

Detection rule:

- if the file starts with the magic bytes, parse it as a headered index
- otherwise treat it as a legacy no-header index

Legacy assumptions:

- data offset = `0`
- index is assumed sorted
- hash prefix width = `64` bits
- dictionary address width = `48` bits
- entry size = `14` bytes

Legacy files still require the caller to supply the algorithm name.

## Compatibility Strategy

- New files written by the tool will use the v1 header.
- Old files remain readable without migration.
- Only headered files get explicit state-machine safety checks.
- Legacy files are trusted for compatibility.

