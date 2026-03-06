use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{bail, Result};
use indicatif::ProgressBar;

use crate::entry::{IndexEntry, ENTRY_SIZE};

impl crate::IndexFile {
    /// Sort the index file in-place with the given memory budget.
    ///
    /// Uses an in-memory buffer for partitions that fit, falling back to
    /// file-based quicksort for larger ones. **Do not interrupt** — the
    /// file will be corrupted if sorting is interrupted.
    pub fn sort(&self, memory_mib: usize, progress: Option<&ProgressBar>) -> Result<()> {
        let mut sorter = IndexSorter::new(memory_mib);
        sorter.sort_file(&self.path, progress)
    }

    /// Sort the index file entirely in RAM.
    ///
    /// Allocates enough memory to hold the entire file. **Do not interrupt.**
    pub fn sort_ram_only(&self, progress: Option<&ProgressBar>) -> Result<()> {
        let mut sorter = IndexSorter::new(0);
        sorter.sort_ram_only_file(&self.path, progress)
    }
}

/// Sorts an index file in-place using a hybrid quicksort algorithm.
///
/// Uses an in-memory buffer for partitions that fit in RAM, falling back
/// to file-based quicksort for larger partitions. This matches the behavior
/// of the original C `sortidx` program.
pub(crate) struct IndexSorter {
    buffer: Vec<IndexEntry>,
    entries_sorted: u64,
    total_entries: u64,
}

impl IndexSorter {
    /// Create a new sorter with the given memory budget in MiB.
    pub fn new(memory_mib: usize) -> Self {
        let buf_bytes = memory_mib * 1024 * 1024;
        let buf_count = buf_bytes / ENTRY_SIZE;
        Self {
            buffer: vec![IndexEntry::new([0; 8], 0); buf_count],
            entries_sorted: 0,
            total_entries: 0,
        }
    }

    /// Sort an index file in-place using hybrid quicksort (in-memory for
    /// partitions that fit, file-based for larger ones).
    pub(crate) fn sort_file(&mut self, index_path: &Path, progress: Option<&ProgressBar>) -> Result<()> {
        let (mut file, num_entries) = self.open_and_validate(index_path)?;
        if num_entries <= 1 {
            return Ok(());
        }

        self.entries_sorted = 0;
        self.total_entries = num_entries;

        let buf_count = self.buffer.len() as i64;
        self.quicksort_file(&mut file, 0, num_entries as i64 - 1, buf_count, progress)?;

        Ok(())
    }

    /// Sort an index file entirely in RAM, allocating as much memory as
    /// needed to hold the entire file.
    pub(crate) fn sort_ram_only_file(
        &mut self,
        index_path: &Path,
        progress: Option<&ProgressBar>,
    ) -> Result<()> {
        let (mut file, num_entries) = self.open_and_validate(index_path)?;
        if num_entries <= 1 {
            return Ok(());
        }

        // Grow buffer to fit the entire file
        let count = num_entries as usize;
        if self.buffer.len() < count {
            self.buffer.resize(count, IndexEntry::new([0; 8], 0));
        }

        self.entries_sorted = 0;
        self.total_entries = num_entries;
        self.sort_partition_in_memory(&mut file, 0, num_entries as i64 - 1, progress)?;

        Ok(())
    }

    fn open_and_validate(&self, index_path: &Path) -> Result<(File, u64)> {
        let file = File::options().read(true).write(true).open(index_path)?;
        let file_size = file.metadata()?.len();

        if file_size % ENTRY_SIZE as u64 != 0 {
            bail!(
                "index file size {} is not a multiple of entry size {}",
                file_size,
                ENTRY_SIZE
            );
        }

        Ok((file, file_size / ENTRY_SIZE as u64))
    }

    fn update_progress(&self, pb: &ProgressBar, action: &str) {
        pb.set_message(format!(
            "{} / {} entries sorted | {}",
            format_count(self.entries_sorted),
            format_count(self.total_entries),
            action,
        ));
        pb.tick();
    }

    fn quicksort_file(
        &mut self,
        file: &mut File,
        lower: i64,
        upper: i64,
        buf_count: i64,
        progress: Option<&ProgressBar>,
    ) -> Result<()> {
        let size = upper - lower + 1;
        if size < 2 {
            return Ok(());
        }

        if size <= buf_count {
            // Fast path: load into memory, sort, write back.
            self.sort_partition_in_memory(file, lower, upper, progress)?;
        } else {
            let pivot = self.partition_file(file, lower, upper, progress)?;

            // Sort smaller partition first to limit stack depth.
            if (pivot - 1) - lower > upper - (pivot + 1) {
                self.quicksort_file(file, pivot + 1, upper, buf_count, progress)?;
                self.quicksort_file(file, lower, pivot - 1, buf_count, progress)?;
            } else {
                self.quicksort_file(file, lower, pivot - 1, buf_count, progress)?;
                self.quicksort_file(file, pivot + 1, upper, buf_count, progress)?;
            }
        }

        Ok(())
    }

    /// Load a partition into the buffer, sort in memory, write back.
    fn sort_partition_in_memory(
        &mut self,
        file: &mut File,
        lower: i64,
        upper: i64,
        progress: Option<&ProgressBar>,
    ) -> Result<()> {
        let count = (upper - lower + 1) as usize;
        let count_fmt = format_count(count as u64);

        if let Some(pb) = progress {
            self.update_progress(pb, &format!("loading {count_fmt} entries into memory"));
        }

        // Bulk read
        file.seek(SeekFrom::Start(lower as u64 * ENTRY_SIZE as u64))?;
        IndexEntry::read_bulk(file, &mut self.buffer, count)?;

        if let Some(pb) = progress {
            self.update_progress(pb, &format!("sorting {count_fmt} entries in memory"));
        }

        // Sort in memory using Rust's PDQ sort
        self.buffer[..count].sort_unstable_by(|a, b| a.compare(b));

        if let Some(pb) = progress {
            self.update_progress(pb, &format!("writing {count_fmt} sorted entries"));
        }

        // Bulk write back
        file.seek(SeekFrom::Start(lower as u64 * ENTRY_SIZE as u64))?;
        IndexEntry::write_bulk(file, &self.buffer, count)?;

        self.entries_sorted += count as u64;
        if let Some(pb) = progress {
            self.update_progress(pb, &format!("sorted {count_fmt} entries in memory"));
        }

        Ok(())
    }

    /// File-based partition for entries that don't fit in memory.
    ///
    /// Per-entry seek+read/write for each entry. Only runs for very large
    /// files that don't fit in the memory buffer.
    fn partition_file(
        &mut self,
        file: &mut File,
        lower: i64,
        upper: i64,
        progress: Option<&ProgressBar>,
    ) -> Result<i64> {
        let pivot_idx = lower + (upper - lower) / 2;

        // Read pivot
        let pivot = read_entry_at(file, pivot_idx)?;

        // Swap pivot to end
        let tmp = read_entry_at(file, upper)?;
        write_entry_at(file, upper, &pivot)?;
        write_entry_at(file, pivot_idx, &tmp)?;

        let partition_size = upper - lower + 1;
        if let Some(pb) = progress {
            self.update_progress(pb, &format!("partitioning {} entries", format_count(partition_size as u64)));
        }

        let mut store_index = lower;

        for i in lower..upper {
            let entry = read_entry_at(file, i)?;
            if entry.compare(&pivot) == std::cmp::Ordering::Less {
                let tmp2 = read_entry_at(file, store_index)?;
                write_entry_at(file, store_index, &entry)?;
                write_entry_at(file, i, &tmp2)?;
                store_index += 1;
            }

            if let Some(pb) = progress {
                if (i - lower) % 100_000 == 0 {
                    let done = (i - lower) as u64;
                    self.update_progress(
                        pb,
                        &format!(
                            "partitioning {} / {} entries",
                            format_count(done),
                            format_count(partition_size as u64),
                        ),
                    );
                }
            }
        }

        // Place pivot at final position
        let tmp2 = read_entry_at(file, store_index)?;
        write_entry_at(file, store_index, &pivot)?;
        write_entry_at(file, upper, &tmp2)?;

        self.entries_sorted += 1;

        Ok(store_index)
    }
}

fn format_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        format!("{n}")
    }
}

fn read_entry_at(file: &mut File, index: i64) -> Result<IndexEntry> {
    file.seek(SeekFrom::Start(index as u64 * ENTRY_SIZE as u64))?;
    let mut hash_prefix = [0u8; 8];
    let mut position = [0u8; 6];
    file.read_exact(&mut hash_prefix)?;
    file.read_exact(&mut position)?;
    Ok(IndexEntry { hash_prefix, position })
}

fn write_entry_at(file: &mut File, index: i64, entry: &IndexEntry) -> Result<()> {
    file.seek(SeekFrom::Start(index as u64 * ENTRY_SIZE as u64))?;
    let hp = entry.hash_prefix;
    let pos = entry.position;
    file.write_all(&hp)?;
    file.write_all(&pos)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checker::check_sorted;
    use crate::hashing::Md5;
    use crate::builder::IndexBuilder;
    use tempfile::NamedTempFile;

    fn test_words_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("test_data")
            .join("words.txt")
    }

    #[test]
    fn test_sort_small_file() {
        let output = NamedTempFile::new().expect("temp file");
        IndexBuilder::build(&Md5, &test_words_path(), output.path(), None)
            .expect("build failed");

        let mut sorter = IndexSorter::new(1); // 1 MiB — more than enough
        sorter.sort_file(output.path(), None).expect("sort failed");

        assert!(
            check_sorted(output.path(), None).expect("check failed"),
            "index should be sorted after sort"
        );
    }

    #[test]
    fn test_sort_already_sorted() {
        // Create, sort, then sort again — should be idempotent
        let output = NamedTempFile::new().expect("temp file");
        IndexBuilder::build(&Md5, &test_words_path(), output.path(), None)
            .expect("build failed");

        let mut sorter = IndexSorter::new(1);
        sorter.sort_file(output.path(), None).expect("first sort failed");
        sorter.sort_file(output.path(), None).expect("second sort failed");

        assert!(
            check_sorted(output.path(), None).expect("check failed"),
            "re-sorted index should still be sorted"
        );
    }

    #[test]
    fn test_sort_forces_file_partition() {
        // Use a tiny buffer so the sorter is forced to do file-based partitioning.
        // We need the buffer to hold fewer entries than the file has.
        let output = NamedTempFile::new().expect("temp file");
        let count = IndexBuilder::build(&Md5, &test_words_path(), output.path(), None)
            .expect("build failed");

        // The words.txt has ~225 entries. Use a buffer of 10 entries to force
        // file-based partitioning.
        let buf_count = 10;
        let mut sorter = IndexSorter {
            buffer: vec![IndexEntry::new([0; 8], 0); buf_count],
            entries_sorted: 0,
            total_entries: 0,
        };
        sorter.sort_file(output.path(), None).expect("sort with tiny buffer failed");

        assert!(
            check_sorted(output.path(), None).expect("check failed"),
            "index sorted with file-based partition should be sorted (entries: {count})"
        );
    }

    #[test]
    fn test_sort_empty_file() {
        let output = NamedTempFile::new().expect("temp file");
        // Empty file is valid (0 entries)
        let mut sorter = IndexSorter::new(1);
        sorter.sort_file(output.path(), None).expect("sort empty file should succeed");
    }

    #[test]
    fn test_sort_single_entry() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        std::io::Write::write_all(&mut wordlist, b"hello\n").expect("write");
        let output = NamedTempFile::new().expect("temp file");
        IndexBuilder::build(&Md5, wordlist.path(), output.path(), None).expect("build");

        let mut sorter = IndexSorter::new(1);
        sorter.sort_file(output.path(), None).expect("sort single entry");
        assert!(check_sorted(output.path(), None).expect("check"));
    }
}
