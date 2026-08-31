//! Thorough tests for the index sorter, with a focus on:
//! - Exact buffer boundary transitions (in-memory vs. file-based)
//! - Already-sorted input idempotency with full data verification
//! - All-identical entries (hash collision stress)
//! - Reverse-sorted input
//! - Data preservation: every entry that goes in comes out
//! - Multi-level file-based partitioning

use std::collections::HashMap;
use std::io::Write;

use preimage::entry::{IndexEntry, ENTRY_SIZE, POSITION_LEN};
use preimage::IndexFile;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use tempfile::NamedTempFile;

/// Write entries to a temp file and return the file.
fn write_entries(entries: &[IndexEntry]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("temp file");
    for e in entries {
        e.write_to(&mut f).expect("write entry");
    }
    f.flush().expect("flush");
    f
}

/// Read all entries back from a file.
fn read_all_entries(path: &std::path::Path) -> Vec<IndexEntry> {
    let data = std::fs::read(path).expect("read file");
    assert_eq!(
        data.len() % ENTRY_SIZE,
        0,
        "file size {} not a multiple of ENTRY_SIZE",
        data.len()
    );
    let count = data.len() / ENTRY_SIZE;
    let mut entries = Vec::with_capacity(count);
    let mut cursor = &data[..];
    for _ in 0..count {
        entries.push(IndexEntry::read_from(&mut cursor).expect("read entry"));
    }
    entries
}

/// Build a fingerprint map: (hash_prefix, position) -> count.
/// Used to verify that sorting preserves all entries exactly.
/// `identical_entries(n)` in the order a correct sort must produce.
///
/// Every prefix is equal, so the tie-break decides the entire order -- and it is not
/// numeric position order. `IndexEntry::compare` falls back to comparing the raw
/// `[u8; POSITION_LEN]` field, which stores the position **little-endian**, so a
/// lexicographic array comparison weighs the least significant byte first: position 256
/// (`[0,1,0,0,0,0]`) sorts before position 1 (`[1,0,0,0,0,0]`).
///
/// Derived from the encoding rather than by calling `compare`, so this predicts the
/// order independently instead of asserting the code against itself.
fn expected_identical_order(n: usize) -> Vec<([u8; 8], u64)> {
    let mut positions: Vec<u64> = (0..n as u64).collect();
    positions.sort_by_key(|p| {
        let mut bytes = [0u8; POSITION_LEN];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = (p >> (i * 8)) as u8;
        }
        bytes
    });
    positions.into_iter().map(|p| ([0xAA; 8], p)).collect()
}

/// The entries in order, as comparable values.
///
/// `IndexEntry` does not derive `PartialEq`, and the tests need order-sensitive equality:
/// the comparator is a total order -- hash prefix, then the raw position bytes -- so a
/// correct sort is deterministic down to the sequence, not just the multiset.
fn entry_order(entries: &[IndexEntry]) -> Vec<([u8; 8], u64)> {
    entries
        .iter()
        .map(|e| (e.hash_prefix, e.position()))
        .collect()
}

fn fingerprint(entries: &[IndexEntry]) -> HashMap<([u8; 8], u64), usize> {
    let mut map = HashMap::new();
    for e in entries {
        *map.entry((e.hash_prefix, e.position())).or_insert(0) += 1;
    }
    map
}

/// Sort with 1 MiB buffer, verify sorted, and return the sorted entries.
/// Sort `entries` and return the result, exercising *both* sorter code paths.
///
/// Which path runs is decided purely by the memory budget: `buf_count` is
/// `memory_bytes / ENTRY_SIZE`, a partition of `size <= buf_count` becomes one
/// `sort_unstable_by`, and anything larger goes through the hand-written file-based
/// Lomuto quicksort. Every input in this file fits comfortably inside the 1 MiB this
/// helper used to hard-code, so none of these tests ever reached `partition_file` --
/// the path the file is named for and the one carrying the real complexity.
///
/// Run each input at three budgets and require byte-identical output:
///   1 MiB           -- in-memory, one sort_unstable_by
///   10 entries      -- multi-level file partitioning
///   0               -- every partition on the file path
///
/// Disagreement between them is itself the bug worth catching.
fn sort_and_verify(entries: &[IndexEntry]) -> Vec<IndexEntry> {
    let mut results: Vec<(usize, Vec<u8>)> = Vec::new();

    for memory_bytes in [1024 * 1024, 10 * ENTRY_SIZE, 0] {
        let f = write_entries(entries);
        let index = IndexFile::open(f.path());
        index
            .sort(memory_bytes, None)
            .unwrap_or_else(|e| panic!("sort failed at budget {memory_bytes}: {e}"));

        assert!(
            index.check_sorted(None).expect("check failed"),
            "index should be sorted at budget {memory_bytes}"
        );

        results.push((memory_bytes, std::fs::read(f.path()).expect("read sorted file")));
    }

    for window in results.windows(2) {
        let (budget_a, bytes_a) = &window[0];
        let (budget_b, bytes_b) = &window[1];
        assert_eq!(
            bytes_a, bytes_b,
            "sorting the same input at budget {budget_a} and {budget_b} produced \
             different files -- the in-memory and file-based paths disagree"
        );
    }

    let f = write_entries(entries);
    std::fs::write(f.path(), &results[0].1).expect("write");
    read_all_entries(f.path())
}

/// Generate N entries with distinct random hash prefixes (seeded for reproducibility).
fn random_entries(n: usize, seed: u64) -> Vec<IndexEntry> {
    let mut rng = SmallRng::seed_from_u64(seed);
    (0..n)
        .map(|i| {
            let mut prefix = [0u8; 8];
            rng.fill(&mut prefix);
            IndexEntry::new(prefix, i as u64)
        })
        .collect()
}

/// Generate N entries all with the same hash prefix.
fn identical_entries(n: usize) -> Vec<IndexEntry> {
    let prefix = [0xAA; 8];
    (0..n).map(|i| IndexEntry::new(prefix, i as u64)).collect()
}

/// Generate entries in reverse sorted order.
fn reverse_sorted_entries(n: usize) -> Vec<IndexEntry> {
    let mut entries: Vec<IndexEntry> = (0..n)
        .map(|i| {
            // Create entries that sort in a known order by making the first byte = i
            let mut prefix = [0u8; 8];
            // Use big-endian style numbering so lexicographic order = numeric order
            let num = i as u64;
            prefix[0] = (num >> 56) as u8;
            prefix[1] = (num >> 48) as u8;
            prefix[2] = (num >> 40) as u8;
            prefix[3] = (num >> 32) as u8;
            prefix[4] = (num >> 24) as u8;
            prefix[5] = (num >> 16) as u8;
            prefix[6] = (num >> 8) as u8;
            prefix[7] = num as u8;
            IndexEntry::new(prefix, i as u64)
        })
        .collect();
    entries.reverse();
    entries
}

// ============================================================
// Buffer boundary tests
// ============================================================
//
// The sorter switches between in-memory sort (when partition fits in buffer)
// and file-based quicksort (when it doesn't). These tests exercise the
// exact boundary.
//
// With 1 MiB buffer: 1 * 1024 * 1024 / 14 = 74898 entries fit in memory.
// We test with sizes around that boundary.

const ENTRIES_PER_MIB: usize = 1024 * 1024 / ENTRY_SIZE; // 74898

#[test]
fn test_sort_exactly_at_buffer_capacity() {
    // Exactly 74898 entries = exactly 1 MiB buffer capacity.
    // Should take the in-memory fast path.
    let entries = random_entries(ENTRIES_PER_MIB, 42);
    let before = fingerprint(&entries);
    let sorted = sort_and_verify(&entries);

    assert_eq!(sorted.len(), ENTRIES_PER_MIB);
    assert_eq!(
        fingerprint(&sorted),
        before,
        "all entries must be preserved"
    );
}

#[test]
fn test_sort_one_over_buffer_capacity() {
    // 74899 entries = one more than fits in 1 MiB buffer.
    // Must use file-based partition for the first split, then both halves
    // will fit in memory.
    let n = ENTRIES_PER_MIB + 1;
    let entries = random_entries(n, 43);
    let before = fingerprint(&entries);
    let sorted = sort_and_verify(&entries);

    assert_eq!(sorted.len(), n);
    assert_eq!(
        fingerprint(&sorted),
        before,
        "all entries must be preserved"
    );
}

#[test]
fn test_sort_one_under_buffer_capacity() {
    // 74897 entries = one less than buffer capacity.
    // Should take the in-memory fast path.
    let n = ENTRIES_PER_MIB - 1;
    let entries = random_entries(n, 44);
    let before = fingerprint(&entries);
    let sorted = sort_and_verify(&entries);

    assert_eq!(sorted.len(), n);
    assert_eq!(
        fingerprint(&sorted),
        before,
        "all entries must be preserved"
    );
}

#[test]
fn test_sort_double_buffer_capacity() {
    // 2x buffer capacity — requires at least one level of file partitioning,
    // and both sub-partitions should fit in memory.
    let n = ENTRIES_PER_MIB * 2;
    let entries = random_entries(n, 45);
    let before = fingerprint(&entries);
    let sorted = sort_and_verify(&entries);

    assert_eq!(sorted.len(), n);
    assert_eq!(
        fingerprint(&sorted),
        before,
        "all entries must be preserved"
    );
}

#[test]
fn test_sort_triple_buffer_capacity() {
    // 3x buffer — may require two levels of file partitioning.
    let n = ENTRIES_PER_MIB * 3;
    let entries = random_entries(n, 46);
    let before = fingerprint(&entries);
    let sorted = sort_and_verify(&entries);

    assert_eq!(sorted.len(), n);
    assert_eq!(
        fingerprint(&sorted),
        before,
        "all entries must be preserved"
    );
}

// ============================================================
// File-based-only sorting (0 MiB buffer)
// ============================================================
//
// With 0 MiB, the buffer holds 0 entries, so every partition goes
// through file-based quicksort — no in-memory fast path at all.

/// Sort with 0 MiB buffer (pure file-based), verify sorted, return entries.
fn sort_file_only(entries: &[IndexEntry]) -> Vec<IndexEntry> {
    let f = write_entries(entries);
    let index = IndexFile::open(f.path());
    index.sort(0, None).expect("sort failed");

    assert!(
        index.check_sorted(None).expect("check failed"),
        "index should be sorted"
    );

    read_all_entries(f.path())
}

#[test]
fn test_sort_file_only_small() {
    let entries = random_entries(100, 200);
    let before = fingerprint(&entries);
    let sorted = sort_file_only(&entries);

    assert_eq!(sorted.len(), 100);
    assert_eq!(
        fingerprint(&sorted),
        before,
        "all entries must be preserved"
    );
}

#[test]
fn test_sort_file_only_with_collisions() {
    // Mix of unique and identical prefixes — exercises file-based
    // partitioning on equal keys without the in-memory fast path.
    let mut entries = Vec::new();
    let mut rng = SmallRng::seed_from_u64(201);

    for i in 0..30 {
        let mut prefix = [0u8; 8];
        rng.fill(&mut prefix);
        entries.push(IndexEntry::new(prefix, i));
    }
    let collision_prefix = [0x77; 8];
    for i in 30..130 {
        entries.push(IndexEntry::new(collision_prefix, i));
    }

    let before = fingerprint(&entries);
    let sorted = sort_file_only(&entries);

    assert_eq!(sorted.len(), 130);
    assert_eq!(
        fingerprint(&sorted),
        before,
        "all entries must be preserved"
    );
}

#[test]
fn test_sort_file_only_reverse_sorted() {
    let entries = reverse_sorted_entries(200);
    let before = fingerprint(&entries);
    let sorted = sort_file_only(&entries);

    assert_eq!(sorted.len(), 200);
    assert_eq!(fingerprint(&sorted), before);
    assert_eq!(sorted[0].hash_prefix, [0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(sorted[199].hash_prefix, [0, 0, 0, 0, 0, 0, 0, 199]);
}

// ============================================================
// Small-scale tests with words.txt
// ============================================================

#[test]
fn test_words_sort_all_in_memory() {
    let words = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test_data")
        .join("words.txt");
    let temp = NamedTempFile::new().expect("temp file");
    let index = IndexFile::build(&preimage::Md5, &words, temp.path(), None).expect("build");

    let before = fingerprint(&read_all_entries(temp.path()));
    index.sort(1024 * 1024, None).expect("sort failed");

    let after = read_all_entries(temp.path());
    assert!(index.check_sorted(None).expect("check"));
    assert_eq!(fingerprint(&after), before, "all entries must be preserved");
}

// ============================================================
// Already-sorted idempotency with full data verification
// ============================================================

#[test]
fn test_sort_already_sorted_preserves_exact_bytes() {
    // Sort once, save exact bytes, sort again, compare byte-for-byte.
    let entries = random_entries(500, 50);
    let f = write_entries(&entries);
    let index = IndexFile::open(f.path());

    index.sort(1024 * 1024, None).expect("first sort");
    let bytes_after_first = std::fs::read(f.path()).expect("read");

    index.sort(1024 * 1024, None).expect("second sort");
    let bytes_after_second = std::fs::read(f.path()).expect("read");

    assert_eq!(
        bytes_after_first, bytes_after_second,
        "sorting an already-sorted file must produce identical bytes"
    );
}

#[test]
fn test_sort_already_sorted_preserves_exact_bytes_large() {
    // Same test but large enough to potentially trigger file-based partition.
    let n = ENTRIES_PER_MIB + 100;
    let entries = random_entries(n, 51);
    let f = write_entries(&entries);
    let index = IndexFile::open(f.path());

    index.sort(1024 * 1024, None).expect("first sort");
    let sorted_once = read_all_entries(f.path());

    index.sort(1024 * 1024, None).expect("second sort");
    let sorted_twice = read_all_entries(f.path());

    // The comparator is a total order -- hash prefix, then file position -- so the sort
    // is fully deterministic and this can be asserted exactly. It used to compare
    // fingerprints "because of randomized tie-breaking", which does not exist: the
    // weaker assertion would have passed on an output that reordered every entry.
    assert!(index.check_sorted(None).expect("check"));
    assert_eq!(
        entry_order(&sorted_once),
        entry_order(&sorted_twice),
        "a deterministic sort must produce the same entries in the same order"
    );

    // Idempotence alone would also hold for a sort that dropped or duplicated entries
    // every time, so check the output against the input as well.
    assert_eq!(
        fingerprint(&sorted_once),
        fingerprint(&entries),
        "every entry that went in must come out, exactly once"
    );
}

// ============================================================
// All-identical entries (worst case for quicksort)
// ============================================================

#[test]
fn test_sort_all_identical_small() {
    // 100 entries sharing one hash prefix: the worst case for quicksort, and the case
    // where the comparator's second key does all the work. `identical_entries` numbers
    // positions 0..n, and the tie-break fixes their order completely, so this asserts
    // the exact sequence rather than that the multiset survived.
    let entries = identical_entries(100);
    let sorted = sort_and_verify(&entries);

    assert_eq!(
        entry_order(&sorted),
        expected_identical_order(100),
        "with every prefix equal, the tie-break fixes the whole order"
    );
}

#[test]
fn test_sort_all_identical_large() {
    // The same at a size that exercises deeper partitioning.
    let entries = identical_entries(10_000);
    let sorted = sort_and_verify(&entries);

    assert_eq!(
        entry_order(&sorted),
        expected_identical_order(10_000),
        "with every prefix equal, the tie-break fixes the whole order"
    );
}

#[test]
fn test_sort_all_identical_exceeding_buffer() {
    // Identical entries that exceed the 1 MiB buffer, forcing file-based partitioning
    // on all-equal keys. This is the pathological case for quicksort, and the one where
    // a partitioning bug is most likely to reorder or lose entries.
    let n = ENTRIES_PER_MIB + 500;
    let entries = identical_entries(n);
    let f = write_entries(&entries);
    let index = IndexFile::open(f.path());

    index
        .sort(1024 * 1024, None)
        .expect("sort all-identical exceeding buffer");
    assert!(index.check_sorted(None).expect("check"));

    let sorted = read_all_entries(f.path());
    assert_eq!(
        entry_order(&sorted),
        expected_identical_order(n),
        "the file-based path must reach the same total order as the in-memory one"
    );
}

// ============================================================
// Reverse-sorted input
// ============================================================

#[test]
fn test_sort_reverse_sorted_small() {
    let entries = reverse_sorted_entries(100);
    let before = fingerprint(&entries);
    let sorted = sort_and_verify(&entries);

    assert_eq!(sorted.len(), 100);
    assert_eq!(fingerprint(&sorted), before);

    // Verify actually reversed: first entry should now have smallest prefix
    assert_eq!(sorted[0].hash_prefix, [0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(sorted[99].hash_prefix, [0, 0, 0, 0, 0, 0, 0, 99]);
}

#[test]
fn test_sort_reverse_sorted_exceeding_buffer() {
    let n = ENTRIES_PER_MIB + 500;
    let entries = reverse_sorted_entries(n);
    let before = fingerprint(&entries);
    let f = write_entries(&entries);
    let index = IndexFile::open(f.path());

    index
        .sort(1024 * 1024, None)
        .expect("sort reverse exceeding buffer");
    assert!(index.check_sorted(None).expect("check"));

    let sorted = read_all_entries(f.path());
    assert_eq!(sorted.len(), n);
    assert_eq!(fingerprint(&sorted), before);
}

// ============================================================
// Edge cases
// ============================================================

#[test]
fn test_sort_two_entries_already_sorted() {
    let entries = vec![
        IndexEntry::new([0x00; 8], 0),
        IndexEntry::new([0xFF; 8], 14),
    ];
    let sorted = sort_and_verify(&entries);
    assert_eq!(sorted[0].hash_prefix, [0x00; 8]);
    assert_eq!(sorted[1].hash_prefix, [0xFF; 8]);
}

#[test]
fn test_sort_two_entries_reversed() {
    let entries = vec![
        IndexEntry::new([0xFF; 8], 0),
        IndexEntry::new([0x00; 8], 14),
    ];
    let sorted = sort_and_verify(&entries);
    assert_eq!(sorted[0].hash_prefix, [0x00; 8]);
    assert_eq!(sorted[1].hash_prefix, [0xFF; 8]);
}

#[test]
fn test_sort_two_entries_identical() {
    let entries = vec![
        IndexEntry::new([0xAB; 8], 0),
        IndexEntry::new([0xAB; 8], 14),
    ];
    let sorted = sort_and_verify(&entries);
    assert_eq!(sorted[0].hash_prefix, [0xAB; 8]);
    assert_eq!(sorted[1].hash_prefix, [0xAB; 8]);
    // Both entries must still be present (different positions)
    let positions: Vec<u64> = sorted.iter().map(|e| e.position()).collect();
    assert!(positions.contains(&0));
    assert!(positions.contains(&14));
}

#[test]
fn test_sort_three_entries_all_orderings() {
    // Test all 6 permutations of 3 distinct entries
    let a = IndexEntry::new([0x11; 8], 0);
    let b = IndexEntry::new([0x22; 8], 14);
    let c = IndexEntry::new([0x33; 8], 28);

    let permutations: Vec<Vec<IndexEntry>> = vec![
        vec![a, b, c],
        vec![a, c, b],
        vec![b, a, c],
        vec![b, c, a],
        vec![c, a, b],
        vec![c, b, a],
    ];

    for (i, perm) in permutations.iter().enumerate() {
        let sorted = sort_and_verify(perm);
        assert_eq!(
            sorted[0].hash_prefix, [0x11; 8],
            "permutation {i}: first should be 0x11"
        );
        assert_eq!(
            sorted[1].hash_prefix, [0x22; 8],
            "permutation {i}: second should be 0x22"
        );
        assert_eq!(
            sorted[2].hash_prefix, [0x33; 8],
            "permutation {i}: third should be 0x33"
        );
    }
}

// ============================================================
// Data preservation under various conditions
// ============================================================

#[test]
fn test_sort_preserves_positions() {
    // Verify that sorting doesn't corrupt the position bytes —
    // each (hash_prefix, position) pair must survive intact.
    let mut entries = Vec::new();
    for i in 0u64..200 {
        let mut prefix = [0u8; 8];
        prefix[7] = (i % 10) as u8; // Only 10 distinct prefixes → many collisions
        entries.push(IndexEntry::new(prefix, i * 100));
    }

    let before = fingerprint(&entries);
    let sorted = sort_and_verify(&entries);

    assert_eq!(sorted.len(), 200);
    assert_eq!(
        fingerprint(&sorted),
        before,
        "all (prefix, position) pairs must survive sorting"
    );
}

#[test]
fn test_sort_preserves_positions_file_based() {
    // Same as above but large enough to trigger file-based partition.
    let n = ENTRIES_PER_MIB + 1000;
    let mut rng = SmallRng::seed_from_u64(99);
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let mut prefix = [0u8; 8];
        // Use only 4 bytes of randomness → many collisions
        let r: u32 = rng.gen();
        prefix[0..4].copy_from_slice(&r.to_be_bytes());
        entries.push(IndexEntry::new(prefix, i as u64));
    }

    let before = fingerprint(&entries);
    let f = write_entries(&entries);
    let index = IndexFile::open(f.path());
    index.sort(1024 * 1024, None).expect("sort");
    assert!(index.check_sorted(None).expect("check"));

    let sorted = read_all_entries(f.path());
    assert_eq!(sorted.len(), n);
    assert_eq!(
        fingerprint(&sorted),
        before,
        "all entries must be preserved in file-based sort"
    );
}

// ============================================================
// Invalid file detection
// ============================================================

#[test]
fn test_sort_rejects_invalid_file_size() {
    let mut f = NamedTempFile::new().expect("temp file");
    // Write 15 bytes — not a multiple of 14
    f.write_all(&[0u8; 15]).expect("write");
    f.flush().expect("flush");

    let index = IndexFile::open(f.path());
    let result = index.sort(1024 * 1024, None);
    assert!(
        result.is_err(),
        "should reject file size not divisible by 14"
    );
}

// ============================================================
// Mixed: some identical, some unique (realistic workload)
// ============================================================

#[test]
fn test_sort_mixed_identical_and_unique() {
    // 50 unique entries + 200 entries all with the same prefix.
    // This creates a distribution where the partition step must handle
    // both the collision block and the dispersed entries.
    let mut entries = Vec::new();
    let mut rng = SmallRng::seed_from_u64(77);

    // 50 unique random entries
    for i in 0..50 {
        let mut prefix = [0u8; 8];
        rng.fill(&mut prefix);
        entries.push(IndexEntry::new(prefix, i));
    }

    // 200 identical entries
    let collision_prefix = [0x55; 8];
    for i in 50..250 {
        entries.push(IndexEntry::new(collision_prefix, i));
    }

    let before = fingerprint(&entries);
    let sorted = sort_and_verify(&entries);

    assert_eq!(sorted.len(), 250);
    assert_eq!(fingerprint(&sorted), before);

    // Verify the collision block is contiguous in the sorted output
    let collision_positions: Vec<usize> = sorted
        .iter()
        .enumerate()
        .filter(|(_, e)| e.hash_prefix == collision_prefix)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(collision_positions.len(), 200);
    // Should be contiguous
    for i in 1..collision_positions.len() {
        assert_eq!(
            collision_positions[i],
            collision_positions[i - 1] + 1,
            "collision block entries should be contiguous"
        );
    }
}
