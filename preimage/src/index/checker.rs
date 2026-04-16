use std::io::{BufReader, Seek, SeekFrom};
use std::path::Path;

use anyhow::Result;
use indicatif::ProgressBar;

use super::entry::{IndexEntry, ENTRY_SIZE};
use super::header::read_index_metadata;

impl super::IndexFile {
    /// Check whether the index file is sorted by hash prefix.
    pub fn check_sorted(&self, progress: Option<&ProgressBar>) -> Result<bool> {
        check_sorted(&self.path, progress)
    }
}

/// Verify that an index file is sorted by hash prefix.
///
/// Returns `true` if every entry's hash prefix is >= the previous entry's.
/// Returns `false` if any out-of-order pair is found.
pub fn check_sorted(index_path: &Path, progress: Option<&ProgressBar>) -> Result<bool> {
    let metadata = read_index_metadata(index_path)?;
    if metadata.entry_count() == 0 {
        return Ok(true);
    }
    assert_eq!(
        metadata.entry_size(),
        ENTRY_SIZE,
        "header parser must reject unsupported entry sizes before checker runs"
    );
    let num_entries = metadata.entry_count();
    if let Some(pb) = progress {
        pb.set_length(num_entries);
    }

    let mut file = std::fs::File::open(index_path)?;
    file.seek(SeekFrom::Start(metadata.data_offset()))?;
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
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_empty_file_is_sorted() {
        let f = NamedTempFile::new().expect("temp file");
        assert!(
            check_sorted(f.path(), None).expect("check"),
            "empty file should be sorted"
        );
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
        IndexEntry::new([0x00; 8], 0)
            .write_to(&mut f)
            .expect("write");
        IndexEntry::new([0x01; 8], 14)
            .write_to(&mut f)
            .expect("write");
        IndexEntry::new([0xFF; 8], 28)
            .write_to(&mut f)
            .expect("write");
        f.flush().expect("flush");
        assert!(check_sorted(f.path(), None).expect("check"));
    }

    #[test]
    fn test_unsorted_entries() {
        let mut f = NamedTempFile::new().expect("temp file");
        IndexEntry::new([0xFF; 8], 0)
            .write_to(&mut f)
            .expect("write");
        IndexEntry::new([0x00; 8], 14)
            .write_to(&mut f)
            .expect("write");
        f.flush().expect("flush");
        assert!(
            !check_sorted(f.path(), None).expect("check"),
            "should detect unsorted"
        );
    }

    #[test]
    fn test_equal_entries_are_sorted() {
        let mut f = NamedTempFile::new().expect("temp file");
        IndexEntry::new([0xAA; 8], 0)
            .write_to(&mut f)
            .expect("write");
        IndexEntry::new([0xAA; 8], 14)
            .write_to(&mut f)
            .expect("write");
        f.flush().expect("flush");
        assert!(
            check_sorted(f.path(), None).expect("check"),
            "equal entries should be sorted"
        );
    }
}
