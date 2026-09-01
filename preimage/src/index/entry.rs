use std::cmp::Ordering;
use std::io::{Read, Write};

pub const HASH_PREFIX_LEN: usize = 8;
pub const POSITION_LEN: usize = 6;
pub const ENTRY_SIZE: usize = HASH_PREFIX_LEN + POSITION_LEN;

/// Maximum position value that fits in 48 bits.
const MAX_POSITION: u64 = 0xFFFF_FFFF_FFFF;

/// Decode a 48-bit little-endian position from a 6-byte slice.
pub fn decode_position(bytes: &[u8; POSITION_LEN]) -> u64 {
    let mut value: u64 = 0;
    for i in (0..POSITION_LEN).rev() {
        value = (value << 8) | bytes[i] as u64;
    }
    value
}

/// A single entry in the index file, matching the C struct layout exactly.
///
/// Layout: [8 bytes hash prefix][6 bytes little-endian position]
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct IndexEntry {
    pub hash_prefix: [u8; HASH_PREFIX_LEN],
    pub position: [u8; POSITION_LEN],
}

// `read_bulk` and `write_bulk` reinterpret a `[IndexEntry]` as `count * ENTRY_SIZE`
// bytes. That is only sound while the struct is exactly ENTRY_SIZE with no padding:
// if a field were widened or added, the two would disagree and the bulk helpers would
// read or write past the entries -- a heap overflow with no compile-time complaint.
//
// This was asserted only in a test, which is the wrong place for an invariant that
// makes `unsafe` sound: a test failure reports it after the fact, whereas this refuses
// to build. Keep it adjacent to the definition so it is not missed when editing.
const _: () = assert!(
    std::mem::size_of::<IndexEntry>() == ENTRY_SIZE,
    "IndexEntry must be exactly ENTRY_SIZE bytes with no padding -- read_bulk and \
     write_bulk transmute slices of it to bytes using that assumption"
);
const _: () = assert!(
    std::mem::align_of::<IndexEntry>() == 1,
    "IndexEntry must be byte-aligned for the bulk byte-slice casts to be sound"
);

impl IndexEntry {
    /// Create a new index entry. Panics if position >= 2^48.
    pub fn new(hash_prefix: [u8; HASH_PREFIX_LEN], position: u64) -> Self {
        assert!(
            position <= MAX_POSITION,
            "position {position:#x} exceeds 48-bit maximum {MAX_POSITION:#x}"
        );
        let mut pos_bytes = [0u8; POSITION_LEN];
        for (i, byte) in pos_bytes.iter_mut().enumerate() {
            *byte = (position >> (i * 8)) as u8;
        }
        Self {
            hash_prefix,
            position: pos_bytes,
        }
    }

    /// Decode the 48-bit little-endian position.
    pub fn position(&self) -> u64 {
        decode_position(&self.position)
    }

    /// A total order over entries: hash prefix first, then the raw position bytes.
    ///
    /// The tie-break compares the stored `[u8; POSITION_LEN]` field lexicographically,
    /// and that field is **little-endian**, so the least significant byte is weighed
    /// first: position 256 (`[0,1,0,0,0,0]`) sorts *before* position 1
    /// (`[1,0,0,0,0,0]`). This is not numeric position order, and calling it "position as
    /// tiebreaker" -- as this comment used to -- invites exactly that misreading. Below
    /// 256 entries the two happen to agree, which is how the misreading survives testing
    /// unless a test uses more than that.
    ///
    /// What the tie-break is for is that it be *total*, not that it be any particular
    /// order: it makes the sort deterministic, so two builds of the same index are
    /// byte-identical. Nothing downstream depends on which order it picks --
    /// `check_sorted` compares prefixes only, because any arrangement within a collision
    /// block is a valid index. `sorter_thorough::expected_identical_order` pins the order
    /// this produces, derived from the encoding rather than from this function.
    pub fn compare(&self, other: &Self) -> Ordering {
        self.compare_prefix(other).then_with(|| {
            let a_pos = self.position;
            let b_pos = other.position;
            a_pos.cmp(&b_pos)
        })
    }

    /// Compare only the hash prefix (for sort verification — any ordering
    /// within a collision block is acceptable).
    pub fn compare_prefix(&self, other: &Self) -> Ordering {
        let a_hp = self.hash_prefix;
        let b_hp = other.hash_prefix;
        a_hp.cmp(&b_hp)
    }

    /// Read a single entry from a reader.
    pub fn read_from(reader: &mut impl Read) -> std::io::Result<Self> {
        let mut entry = Self {
            hash_prefix: [0; HASH_PREFIX_LEN],
            position: [0; POSITION_LEN],
        };
        reader.read_exact(&mut entry.hash_prefix)?;
        reader.read_exact(&mut entry.position)?;
        Ok(entry)
    }

    /// Write a single entry to a writer.
    pub fn write_to(&self, writer: &mut impl Write) -> std::io::Result<()> {
        let hp = self.hash_prefix;
        let pos = self.position;
        writer.write_all(&hp)?;
        writer.write_all(&pos)?;
        Ok(())
    }

    /// Bulk read `count` entries into `buf[..count]` via a single `read_exact`.
    ///
    /// # Panics
    ///
    /// Panics if `count > buf.len()`. That check is load-bearing rather than defensive:
    /// it is what keeps the reinterpreted byte slice inside the allocation.
    pub fn read_bulk(
        reader: &mut impl Read,
        buf: &mut [Self],
        count: usize,
    ) -> std::io::Result<()> {
        assert!(
            count <= buf.len(),
            "count {count} exceeds buffer length {}",
            buf.len()
        );
        if count == 0 {
            return Ok(());
        }
        let byte_len = count * ENTRY_SIZE;
        // SAFETY: `from_raw_parts_mut` needs the pointer valid for `byte_len` bytes,
        // properly aligned, and exclusively borrowed. All three hold:
        //
        // * **Length.** `byte_len` is `count * ENTRY_SIZE`, and the `const _` assertion
        //   beside the struct definition makes `size_of::<IndexEntry>() == ENTRY_SIZE` a
        //   compile error if it ever stops being true, so `count` entries occupy exactly
        //   `byte_len` bytes. The assert above bounds `count` by `buf.len()`, so those
        //   bytes are inside the allocation. Widening a field without noticing is the
        //   failure this pair of checks exists to prevent, and it cannot compile.
        // * **Alignment.** `[u8]` requires alignment 1, which any pointer satisfies.
        // * **Aliasing.** `buf` is `&mut`, so this is the only live reference to those
        //   bytes for the duration of the borrow.
        //
        // Writing arbitrary bytes into them is sound because every field is a `[u8; N]`:
        // the type has no padding and no invalid bit patterns, so whatever the reader
        // produces is a valid `IndexEntry` -- possibly a meaningless one, which is a
        // data-integrity question rather than a soundness one.
        let byte_slice =
            unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, byte_len) };
        reader.read_exact(byte_slice)
    }

    /// Bulk write `count` entries from `buf[..count]` via a single `write_all`.
    ///
    /// # Panics
    ///
    /// Panics if `count > buf.len()`, for the same reason as `read_bulk`.
    pub fn write_bulk(writer: &mut impl Write, buf: &[Self], count: usize) -> std::io::Result<()> {
        assert!(
            count <= buf.len(),
            "count {count} exceeds buffer length {}",
            buf.len()
        );
        if count == 0 {
            return Ok(());
        }
        let byte_len = count * ENTRY_SIZE;
        // SAFETY: as in `read_bulk`, but shared rather than exclusive. `byte_len` is
        // within the allocation because the `const _` assertion pins
        // `size_of::<IndexEntry>()` to `ENTRY_SIZE` at compile time and the assert above
        // bounds `count` by `buf.len()`; `[u8]` needs alignment 1; and `buf` is a shared
        // borrow, so no `&mut` to these bytes can exist while this slice does.
        let byte_slice = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, byte_len) };
        writer.write_all(byte_slice)
    }
}

impl std::fmt::Debug for IndexEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hp = self.hash_prefix;
        f.debug_struct("IndexEntry")
            .field("hash_prefix", &hex::encode(hp))
            .field("position", &self.position())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_position_roundtrip() {
        let positions: &[u64] = &[0, 1, 255, 256, 65535, 0x0001_0000, 0xFFFF_FFFF_FFFF];
        for &pos in positions {
            let entry = IndexEntry::new([0; 8], pos);
            assert_eq!(
                entry.position(),
                pos,
                "position roundtrip failed for {pos:#x}"
            );
        }
    }

    #[test]
    #[should_panic(expected = "exceeds 48-bit maximum")]
    fn test_position_overflow_panics() {
        IndexEntry::new([0; 8], MAX_POSITION + 1);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let original = IndexEntry::new([1, 2, 3, 4, 5, 6, 7, 8], 0xABCDEF);
        let mut buf = Vec::new();
        original.write_to(&mut buf).expect("write failed");
        assert_eq!(buf.len(), ENTRY_SIZE);

        let restored = IndexEntry::read_from(&mut &buf[..]).expect("read failed");
        assert_eq!(original.hash_prefix, restored.hash_prefix);
        assert_eq!(original.position(), restored.position());
    }

    #[test]
    fn test_entry_size() {
        assert_eq!(std::mem::size_of::<IndexEntry>(), ENTRY_SIZE);
    }

    #[test]
    fn test_comparison_ordering() {
        let a = IndexEntry::new([0, 0, 0, 0, 0, 0, 0, 1], 0);
        let b = IndexEntry::new([0, 0, 0, 0, 0, 0, 0, 2], 0);
        let c = IndexEntry::new([1, 0, 0, 0, 0, 0, 0, 0], 0);
        let d = IndexEntry::new([0, 0, 0, 0, 0, 0, 0, 1], 999);

        assert_eq!(a.compare(&b), Ordering::Less);
        assert_eq!(b.compare(&a), Ordering::Greater);
        assert_eq!(a.compare(&c), Ordering::Less);
        assert_eq!(c.compare(&a), Ordering::Greater);
        // Same hash prefix, different position — tiebreaks by position
        assert_eq!(a.compare(&d), Ordering::Less);
        assert_eq!(d.compare(&a), Ordering::Greater);
        // Truly identical entries are equal
        let a2 = IndexEntry::new([0, 0, 0, 0, 0, 0, 0, 1], 0);
        assert_eq!(a.compare(&a2), Ordering::Equal);
    }

    #[test]
    fn test_bulk_read_write_roundtrip() {
        let entries = vec![
            IndexEntry::new([0xAA; 8], 100),
            IndexEntry::new([0xBB; 8], 200),
            IndexEntry::new([0xCC; 8], 300),
        ];

        let mut buf = Vec::new();
        IndexEntry::write_bulk(&mut buf, &entries, 3).expect("bulk write failed");
        assert_eq!(buf.len(), 3 * ENTRY_SIZE);

        let mut read_buf = vec![IndexEntry::new([0; 8], 0); 3];
        IndexEntry::read_bulk(&mut &buf[..], &mut read_buf, 3).expect("bulk read failed");

        for (orig, restored) in entries.iter().zip(read_buf.iter()) {
            assert_eq!(orig.hash_prefix, restored.hash_prefix);
            assert_eq!(orig.position(), restored.position());
        }
    }

    #[test]
    fn test_position_encoding_matches_php() {
        // PHP encodeTo48Bits encodes as little-endian.
        // Position 0x123456 should be bytes [0x56, 0x34, 0x12, 0x00, 0x00, 0x00]
        let entry = IndexEntry::new([0; 8], 0x123456);
        let pos = entry.position;
        assert_eq!(pos, [0x56, 0x34, 0x12, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_bulk_zero_count() {
        let mut buf = Vec::new();
        IndexEntry::write_bulk(&mut buf, &[], 0).expect("bulk write zero failed");
        assert!(buf.is_empty());

        let mut read_buf: Vec<IndexEntry> = Vec::new();
        IndexEntry::read_bulk(&mut &[][..], &mut read_buf, 0).expect("bulk read zero failed");
    }
}
