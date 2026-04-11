# Index Header Implementation Progress

This file tracks the planned headered-index work and the remaining implementation steps.

## Decisions

- New indexes will use a fixed-size 256-byte header.
- Legacy no-header indexes must remain supported.
- The caller must always supply the algorithm name.
- For headered indexes, the embedded hash name is a strict sanity check against the user-supplied algorithm.
- Parsing is strict, not Postel-style.
- For headered indexes, lookup will trust the `Sorted` state bit rather than re-running a structural sort check on open.
- Legacy indexes are assumed sorted for backward compatibility.

## Header v1 Summary

- Magic: `PREIMAGE-IDX\0\0\0\0`
- Header version: `1`
- State enum:
  - `1 = Creating`
  - `2 = Created`
  - `3 = Sorting`
  - `4 = Sorted`
- Hash name: ASCII, NUL-padded, 128 bytes
- Hash prefix width: bit-based, but v1 only accepts `64`
- Dictionary address width: bit-based, but v1 only accepts `48`
- Entry count: redundant integrity check
- Reserved bytes: must be zero

## Compatibility Rules

- If the file starts with the header magic, parse it as headered `v1`.
- Otherwise treat it as a legacy no-header index.
- Legacy assumptions:
  - sorted
  - data offset = `0`
  - hash prefix bits = `64`
  - dictionary address bits = `48`
  - entry size = `14`

## Strict Parsing Rules

For headered indexes, reject on any of the following:

- Unknown header version
- Unknown state
- Non-ASCII hash name
- Unsupported hash name
- Supplied algorithm does not exactly match header hash name
- Nonzero reserved bytes
- Unsupported hash prefix width
- Unsupported dictionary address width
- Entry count inconsistent with payload size
- State is `Creating`
- State is `Sorting`
- State is `Created` for lookup

## Implementation Checklist

- [ ] Add `preimage/src/index/header.rs`
- [ ] Define header constants and byte layout
- [ ] Define `IndexState`
- [ ] Implement header encode/decode helpers
- [ ] Implement strict header validation
- [ ] Add index format detection (`HeaderV1` vs `Legacy`)
- [ ] Centralize metadata parsing for index operations
- [ ] Update builder to write headered files
- [ ] Set `Creating` at build start
- [ ] Finalize build as `Created`
- [ ] Update sorter to operate after header offset
- [ ] Set `Sorting` before sort starts
- [ ] Finalize sort as `Sorted`
- [ ] Update checker to understand headered and legacy files
- [ ] Update lookup open path to validate headered state and algorithm match
- [ ] Update `IndexFile::entry_count` to use parsed metadata
- [ ] Update benchmark/oracle/CLI codepaths to use shared parsing behavior
- [ ] Add unit tests for header parse/validate
- [ ] Add integration tests for headered create/sort/lookup flow
- [ ] Add integration tests for legacy compatibility
- [ ] Add integration tests for interrupted create detection
- [ ] Add integration tests for interrupted sort detection
- [ ] Add integration tests for wrong-algorithm rejection

## High-Impact Tests To Add

### Compatibility

- [ ] Open and use an existing legacy no-header index successfully
- [ ] Build, sort, and use a new headered index successfully
- [ ] Confirm legacy indexes are still assumed sorted

### Header Validation

- [ ] Reject unknown header version
- [ ] Reject nonzero reserved bytes
- [ ] Reject unsupported hash prefix width
- [ ] Reject unsupported dictionary address width
- [ ] Reject payload size that is not divisible by derived entry size
- [ ] Reject entry-count mismatch against payload size
- [ ] Reject non-ASCII hash name
- [ ] Reject unsupported ASCII hash name
- [ ] Reject user-supplied algorithm mismatch

### State Handling

- [ ] `create` writes `Creating` first and finalizes to `Created`
- [ ] `sort` transitions `Created -> Sorting -> Sorted`
- [ ] Opening `Creating` fails as interrupted/incomplete create
- [ ] Opening `Sorting` fails as interrupted/corrupt sort
- [ ] Lookup on `Created` fails because it is not sorted yet
- [ ] Lookup on `Sorted` succeeds without a structural sort scan

### Corruption / Truncation

- [ ] Reject truncation inside the 256-byte header
- [ ] Reject truncation after header but before full payload
- [ ] Reject malformed payload sizing for headered indexes

### CLI / Integration

- [ ] `preimage create` produces headered files in `Created`
- [ ] `preimage sort` leaves files in `Sorted`
- [ ] `preimage lookup` rejects headered index with the wrong algorithm
- [ ] `preimage lookup` still works with legacy no-header indexes
- [ ] `preimage check` works with both headered and legacy indexes
- [ ] Benchmark path handles both headered and legacy indexes

