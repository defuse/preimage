use std::io::BufReader;
use std::path::Path;

use anyhow::Result;
use indicatif::ProgressBar;

use crate::entry::{IndexEntry, ENTRY_SIZE};

/// Verify that an index file is sorted by hash prefix.
///
/// Returns `true` if every entry's hash prefix is >= the previous entry's.
/// Returns `false` if any out-of-order pair is found.
pub fn check_sorted(index_path: &Path, progress: Option<&ProgressBar>) -> Result<bool> {
    let file = std::fs::File::open(index_path)?;
    let file_size = file.metadata()?.len();

    if file_size == 0 {
        return Ok(true);
    }

    if file_size % ENTRY_SIZE as u64 != 0 {
        anyhow::bail!(
            "index file size {} is not a multiple of entry size {}",
            file_size,
            ENTRY_SIZE
        );
    }

    let num_entries = file_size / ENTRY_SIZE as u64;
    if let Some(pb) = progress {
        pb.set_length(num_entries);
    }

    let mut reader = BufReader::new(file);
    let mut prev = IndexEntry::read_from(&mut reader)?;

    for i in 1..num_entries {
        let current = IndexEntry::read_from(&mut reader)?;
        if current.compare_prefix(&prev) == std::cmp::Ordering::Less {
            return Ok(false);
        }
        prev = current;

        if let Some(pb) = progress {
            if i % 10_000_000 == 0 {
                pb.set_position(i);
            }
        }
    }

    if let Some(pb) = progress {
        pb.set_position(num_entries);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::IndexEntry;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_empty_file_is_sorted() {
        let f = NamedTempFile::new().expect("temp file");
        assert!(check_sorted(f.path(), None).expect("check"), "empty file should be sorted");
    }

    #[test]
    fn test_single_entry_is_sorted() {
        let mut f = NamedTempFile::new().expect("temp file");
        let entry = IndexEntry::new([0xAA; 8], 0);
        entry.write_to(&mut f).expect("write");
        f.flush().expect("flush");
        assert!(check_sorted(f.path(), None).expect("check"));
    }

    #[test]
    fn test_sorted_entries() {
        let mut f = NamedTempFile::new().expect("temp file");
        IndexEntry::new([0x00; 8], 0).write_to(&mut f).expect("write");
        IndexEntry::new([0x01; 8], 14).write_to(&mut f).expect("write");
        IndexEntry::new([0xFF; 8], 28).write_to(&mut f).expect("write");
        f.flush().expect("flush");
        assert!(check_sorted(f.path(), None).expect("check"));
    }

    #[test]
    fn test_unsorted_entries() {
        let mut f = NamedTempFile::new().expect("temp file");
        IndexEntry::new([0xFF; 8], 0).write_to(&mut f).expect("write");
        IndexEntry::new([0x00; 8], 14).write_to(&mut f).expect("write");
        f.flush().expect("flush");
        assert!(!check_sorted(f.path(), None).expect("check"), "should detect unsorted");
    }

    #[test]
    fn test_equal_entries_are_sorted() {
        let mut f = NamedTempFile::new().expect("temp file");
        IndexEntry::new([0xAA; 8], 0).write_to(&mut f).expect("write");
        IndexEntry::new([0xAA; 8], 14).write_to(&mut f).expect("write");
        f.flush().expect("flush");
        assert!(check_sorted(f.path(), None).expect("check"), "equal entries should be sorted");
    }
}
