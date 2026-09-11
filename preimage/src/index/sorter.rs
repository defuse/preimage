use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::fs::File;
use std::io::{BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use indicatif::ProgressBar;

use super::entry::{IndexEntry, ENTRY_SIZE};

impl super::IndexFile {
    /// Sort the index file in-place with the given memory budget (in bytes).
    ///
    /// Files that fit in the budget are sorted in one in-memory pass. Larger
    /// files are sorted with an external merge sort: sorted runs the size of the
    /// budget are written back in place, then merged. **Do not interrupt** — the
    /// file will be corrupted if sorting is interrupted.
    pub fn sort(&self, memory_bytes: usize, progress: Option<&ProgressBar>) -> Result<()> {
        let mut sorter = IndexSorter::new(memory_bytes);
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

/// Smallest run the external path will create, in entries.
///
/// It only matters when the requested budget is smaller than this (e.g. a
/// deliberately tiny `--memory`, or the `0` the tests use to force the external
/// path). Flooring the run length here keeps the run count — and therefore the
/// number of files open at once during the merge — bounded even then: without
/// it, a near-zero budget on a huge index would ask for one run per handful of
/// entries and exhaust file descriptors. 64Ki entries is ~896 KiB per run.
const MIN_RUN_ENTRIES: usize = 64 * 1024;

/// Per-stream I/O buffer floor, in bytes. Each run reader and the merge writer
/// gets at least this much so the merge does large sequential reads and writes
/// rather than one syscall per entry.
const MIN_STREAM_BYTES: usize = 64 * 1024;

/// Upper bound on how many runs are merged at once. Bounds both the number of
/// files open simultaneously and the heap size; when there are more runs than
/// this, the merge runs in multiple passes. Realistic budgets never reach it —
/// a 2 GiB budget over a 17 GB index makes ~9 runs — so it exists only to keep
/// the degenerate tiny-budget case from opening thousands of file handles.
const MAX_FAN_IN: usize = 512;

/// Sorts an index file in-place.
///
/// Files that fit in the memory budget are sorted with a single load / sort /
/// write-back. Anything larger is sorted by external merge sort: one pass writes
/// budget-sized sorted runs back over the file, then a k-way merge (multi-pass
/// if there are more runs than the fan-in) streams the runs into a sibling
/// temp file, which is renamed over the original.
///
/// The comparator [`IndexEntry::compare`] is a total order — hash prefix, then
/// the unique wordlist position — so every path here produces the same
/// byte-for-byte output regardless of budget.
pub(crate) struct IndexSorter {
    buffer: Vec<IndexEntry>,
    memory_bytes: usize,
    entries_sorted: u64,
    total_entries: u64,
}

impl IndexSorter {
    /// Create a new sorter with the given memory budget in bytes.
    pub fn new(memory_bytes: usize) -> Self {
        Self {
            buffer: Vec::new(),
            memory_bytes,
            entries_sorted: 0,
            total_entries: 0,
        }
    }

    /// Sort an index file in-place (in-memory when it fits the budget, external
    /// merge sort otherwise).
    pub(crate) fn sort_file(
        &mut self,
        index_path: &Path,
        progress: Option<&ProgressBar>,
    ) -> Result<()> {
        let (file, num_entries) = self.open_and_validate(index_path)?;
        if num_entries <= 1 {
            return Ok(());
        }

        self.entries_sorted = 0;
        self.total_entries = num_entries;

        let buf_count = self.memory_bytes / ENTRY_SIZE;

        // Whole file fits in the requested budget: one in-memory sort, no temp file.
        if num_entries <= buf_count as u64 {
            let mut file = file;
            let count = num_entries as usize;
            self.buffer = vec![IndexEntry::new([0; 8], 0); count];
            self.sort_range_in_memory(&mut file, 0, count, progress)?;
            return Ok(());
        }

        // Too big to hold at once: external merge sort. `run_entries` is the
        // in-memory chunk each run is sorted in; floor it so a tiny budget still
        // makes a bounded number of runs.
        let run_entries = buf_count.max(MIN_RUN_ENTRIES);
        let tmp_path = sort_tmp_path(index_path);

        let result = self.external_sort(file, index_path, &tmp_path, num_entries, run_entries, progress);

        // A failed sort must not leave the scratch file behind. On success the
        // temp file has either been renamed onto the index or already removed.
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        result
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

        // Grow buffer to fit the entire file.
        //
        // `num_entries as usize` silently truncates where usize is 32 bits, so an
        // index of more than 2^32 entries -- 56 GiB, which is the scale this tool is
        // for -- would allocate a buffer for `num_entries mod 2^32`, sort that prefix,
        // and report success on a file that is still unsorted past it. Every
        // downstream check would pass: the size is still a multiple of ENTRY_SIZE and
        // check_sorted is not wired into any runtime path. Refuse instead.
        let count = usize::try_from(num_entries).unwrap_or_else(|_| {
            panic!(
                "index holds {num_entries} entries, which does not fit in this \
                 platform's usize ({} bits). Sorting it here would silently sort only \
                 the first {} entries and report success. Use a 64-bit build.",
                usize::BITS,
                usize::MAX,
            )
        });
        // `try_reserve` rather than letting `resize` allocate: a plain `resize` that
        // cannot get the memory calls `handle_alloc_error`, which *aborts* the process --
        // there is no error for the CLI to report, and `--ram` promises one. This turns a
        // refused allocation into a message naming the size that was refused.
        //
        // It does not make the promise unconditional, and the help text no longer claims
        // it does. Under Linux's default overcommit the kernel grants the reservation and
        // the process is killed when it touches the pages, so the honest guarantee is
        // "errors if the allocator refuses", not "errors if it will not fit".
        if self.buffer.len() < count {
            let extra = count - self.buffer.len();
            self.buffer.try_reserve(extra).map_err(|e| {
                anyhow::anyhow!(
                    "could not allocate {} entries ({} bytes) to sort this index in RAM: {e}. \
                     Sort without --ram to use the file-based path instead.",
                    count,
                    count.saturating_mul(ENTRY_SIZE),
                )
            })?;
            self.buffer.resize(count, IndexEntry::new([0; 8], 0));
        }

        self.entries_sorted = 0;
        self.total_entries = num_entries;
        self.sort_range_in_memory(&mut file, 0, count, progress)?;

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

    /// Load `count` entries starting at `start` into the buffer, sort them in
    /// memory, and write them back to the same place.
    fn sort_range_in_memory(
        &mut self,
        file: &mut File,
        start: u64,
        count: usize,
        progress: Option<&ProgressBar>,
    ) -> Result<()> {
        debug_assert!(count <= self.buffer.len());
        let count_fmt = format_count(count as u64);
        let byte_start = start * ENTRY_SIZE as u64;

        if let Some(pb) = progress {
            self.update_progress(pb, &format!("loading {count_fmt} entries into memory"));
        }

        file.seek(SeekFrom::Start(byte_start))?;
        IndexEntry::read_bulk(file, &mut self.buffer, count)?;

        if let Some(pb) = progress {
            self.update_progress(pb, &format!("sorting {count_fmt} entries in memory"));
        }

        // Rust's PDQ sort. Unstable is fine: the comparator is a total order, so
        // there are no equal elements whose relative order could differ.
        self.buffer[..count].sort_unstable_by(|a, b| a.compare(b));

        if let Some(pb) = progress {
            self.update_progress(pb, &format!("writing {count_fmt} sorted entries"));
        }

        file.seek(SeekFrom::Start(byte_start))?;
        IndexEntry::write_bulk(file, &self.buffer, count)?;

        self.entries_sorted += count as u64;
        Ok(())
    }

    /// External merge sort for indexes larger than the memory budget.
    ///
    /// `file` is the read+write handle to the index from [`open_and_validate`];
    /// it is consumed once the in-place run-generation pass is done so the file
    /// can be reopened for the merge.
    fn external_sort(
        &mut self,
        file: File,
        index_path: &Path,
        tmp_path: &Path,
        num_entries: u64,
        run_entries: usize,
        progress: Option<&ProgressBar>,
    ) -> Result<()> {
        // Phase 1: turn the file into a sequence of sorted runs, in place.
        let runs = self.generate_runs(file, num_entries, run_entries, progress)?;

        // When the budget is below MIN_RUN_ENTRIES but the file is smaller still,
        // run generation sorts the whole thing as one run, in place — nothing to
        // merge, and no scratch file was created.
        if runs.len() <= 1 {
            return Ok(());
        }

        // Phase 2: merge the runs. Each pass merges groups of up to `fan_in`
        // runs, ping-ponging between the index file and the scratch file, until
        // one run remains. `entries_sorted` is reset because the merge re-touches
        // every entry — the progress bar now tracks merge progress.
        let (fan_in, stream_bytes) = self.merge_layout(runs.len());
        self.entries_sorted = 0;

        let mut runs = runs;
        let mut src = index_path.to_path_buf();
        let mut dst = tmp_path.to_path_buf();

        while runs.len() > 1 {
            runs = self.merge_pass(&src, &dst, &runs, fan_in, stream_bytes, progress)?;
            std::mem::swap(&mut src, &mut dst);
        }

        // The fully merged data now lives in `src`. If that is the scratch file,
        // move it onto the index; otherwise the index already holds it and the
        // scratch file (if any pass created it) is stale.
        if src == tmp_path {
            std::fs::rename(&src, index_path)?;
        } else {
            let _ = std::fs::remove_file(tmp_path);
        }

        Ok(())
    }

    /// Phase 1: sort successive `run_entries`-sized chunks in memory and write
    /// each back in place. Returns the `(start, len)` of every run, in entries.
    fn generate_runs(
        &mut self,
        mut file: File,
        num_entries: u64,
        run_entries: usize,
        progress: Option<&ProgressBar>,
    ) -> Result<Vec<(u64, u64)>> {
        self.buffer = vec![IndexEntry::new([0; 8], 0); run_entries];

        let mut runs = Vec::new();
        let mut start = 0u64;
        while start < num_entries {
            let count = run_entries.min((num_entries - start) as usize);
            self.sort_range_in_memory(&mut file, start, count, progress)?;
            runs.push((start, count as u64));
            start += count as u64;
        }

        // Drop the buffer and the handle: the merge reopens the file and needs
        // the memory for its stream buffers instead.
        self.buffer = Vec::new();
        file.flush().ok();
        drop(file);

        Ok(runs)
    }

    /// Decide how many runs to merge at once and how large each stream buffer is,
    /// spending the memory budget across `fan_in` readers plus one writer.
    fn merge_layout(&self, num_runs: usize) -> (usize, usize) {
        let budget = self.memory_bytes.max(MIN_STREAM_BYTES * 3);
        // Enough streams to use the budget at the minimum buffer size, but never
        // more than we have runs or the fan-in cap.
        let by_budget = (budget / MIN_STREAM_BYTES).max(2);
        let fan_in = by_budget.min(MAX_FAN_IN).min(num_runs).max(2);
        // Split the budget across the readers and the single writer.
        let stream_bytes = (budget / (fan_in + 1)).max(MIN_STREAM_BYTES);
        (fan_in, stream_bytes)
    }

    /// One merge pass: merge consecutive groups of up to `fan_in` runs from
    /// `src` into `dst`, laid out end to end, and return the new run list.
    fn merge_pass(
        &mut self,
        src: &Path,
        dst: &Path,
        runs: &[(u64, u64)],
        fan_in: usize,
        stream_bytes: usize,
        progress: Option<&ProgressBar>,
    ) -> Result<Vec<(u64, u64)>> {
        let mut writer = File::create(dst)?;
        let mut out_runs = Vec::with_capacity(runs.len().div_ceil(fan_in));
        let mut out_start = 0u64;

        for group in runs.chunks(fan_in) {
            let merged_len: u64 = group.iter().map(|(_, len)| *len).sum();
            self.merge_group(src, &mut writer, group, stream_bytes, progress)?;
            out_runs.push((out_start, merged_len));
            out_start += merged_len;
        }

        writer.flush()?;
        Ok(out_runs)
    }

    /// Merge one group of runs from `src`, appending the sorted result to
    /// `writer` (which is written strictly sequentially across groups).
    fn merge_group(
        &mut self,
        src: &Path,
        writer: &mut File,
        group: &[(u64, u64)],
        stream_bytes: usize,
        progress: Option<&ProgressBar>,
    ) -> Result<()> {
        let mut readers: Vec<RunReader> = Vec::with_capacity(group.len());
        let mut heap: BinaryHeap<HeapItem> = BinaryHeap::with_capacity(group.len());

        for &(start, len) in group {
            let mut reader = RunReader::open(src, start, len, stream_bytes)?;
            if let Some(entry) = reader.next_entry()? {
                heap.push(HeapItem {
                    key: entry,
                    run: readers.len(),
                });
            }
            readers.push(reader);
        }

        let out_batch = (stream_bytes / ENTRY_SIZE).max(1);
        let mut out_buf: Vec<IndexEntry> = Vec::with_capacity(out_batch);

        while let Some(HeapItem { key, run }) = heap.pop() {
            out_buf.push(key);
            if out_buf.len() == out_batch {
                IndexEntry::write_bulk(writer, &out_buf, out_buf.len())?;
                out_buf.clear();
            }

            if let Some(entry) = readers[run].next_entry()? {
                heap.push(HeapItem { key: entry, run });
            }

            self.entries_sorted += 1;
            if let Some(pb) = progress {
                if self.entries_sorted % 1_000_000 == 0 {
                    self.update_progress(pb, "merging runs");
                }
            }
        }

        if !out_buf.is_empty() {
            IndexEntry::write_bulk(writer, &out_buf, out_buf.len())?;
        }

        Ok(())
    }
}

/// A sibling scratch path next to the index, so the final rename stays on the
/// same filesystem and does not fall back to a copy.
fn sort_tmp_path(index_path: &Path) -> PathBuf {
    let mut name = index_path.as_os_str().to_owned();
    name.push(".preimage-sort-tmp");
    PathBuf::from(name)
}

/// A buffered forward reader over one sorted run: a bounded `[start, start+len)`
/// slice of a file, handed out one entry at a time.
struct RunReader {
    reader: BufReader<File>,
    remaining: u64,
}

impl RunReader {
    fn open(path: &Path, start: u64, len: u64, buf_bytes: usize) -> Result<Self> {
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(start * ENTRY_SIZE as u64))?;
        Ok(Self {
            reader: BufReader::with_capacity(buf_bytes.max(ENTRY_SIZE), file),
            remaining: len,
        })
    }

    fn next_entry(&mut self) -> Result<Option<IndexEntry>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let entry = IndexEntry::read_from(&mut self.reader)?;
        self.remaining -= 1;
        Ok(Some(entry))
    }
}

/// A run's current head entry, tagged with the run it came from, ordered for a
/// min-heap on [`IndexEntry::compare`].
struct HeapItem {
    key: IndexEntry,
    run: usize,
}

impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // `BinaryHeap` is a max-heap, so invert: the smallest key must compare
        // "greatest" to pop first. The `run` tie-break only makes the order
        // total for the heap's sake; the comparator itself never ties, because
        // wordlist positions are unique.
        other
            .key
            .compare(&self.key)
            .then_with(|| other.run.cmp(&self.run))
    }
}

impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for HeapItem {}

fn format_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        format!("{n}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::builder::IndexBuilder;
    use crate::index::checker::check_sorted;
    use crate::Md5;
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
        IndexBuilder::build(&Md5, &test_words_path(), output.path(), None).expect("build failed");

        let mut sorter = IndexSorter::new(1024 * 1024);
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
        IndexBuilder::build(&Md5, &test_words_path(), output.path(), None).expect("build failed");

        let mut sorter = IndexSorter::new(1024 * 1024);
        sorter
            .sort_file(output.path(), None)
            .expect("first sort failed");
        sorter
            .sort_file(output.path(), None)
            .expect("second sort failed");

        assert!(
            check_sorted(output.path(), None).expect("check failed"),
            "re-sorted index should still be sorted"
        );
    }

    #[test]
    fn test_sort_forces_external_merge() {
        // Use a tiny buffer so the sorter is forced through the external merge
        // path (many runs, merged) rather than the in-memory fast path.
        let output = NamedTempFile::new().expect("temp file");
        let count = IndexBuilder::build(&Md5, &test_words_path(), output.path(), None)
            .expect("build failed");

        // A budget of 10 entries is far below MIN_RUN_ENTRIES, so runs are
        // floored to MIN_RUN_ENTRIES; words.txt is tiny, so this still fits one
        // run. Assert correctness regardless of which path ran.
        let mut sorter = IndexSorter::new(10 * ENTRY_SIZE);
        sorter
            .sort_file(output.path(), None)
            .expect("sort with tiny buffer failed");

        assert!(
            check_sorted(output.path(), None).expect("check failed"),
            "index sorted with tiny buffer should be sorted (entries: {count})"
        );
    }

    #[test]
    fn test_sort_empty_file() {
        let output = NamedTempFile::new().expect("temp file");
        // Empty file is valid (0 entries)
        let mut sorter = IndexSorter::new(1024 * 1024);
        sorter
            .sort_file(output.path(), None)
            .expect("sort empty file should succeed");
    }

    #[test]
    fn test_sort_single_entry() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        std::io::Write::write_all(&mut wordlist, b"hello\n").expect("write");
        let output = NamedTempFile::new().expect("temp file");
        IndexBuilder::build(&Md5, wordlist.path(), output.path(), None).expect("build");

        let mut sorter = IndexSorter::new(1024 * 1024);
        sorter
            .sort_file(output.path(), None)
            .expect("sort single entry");
        assert!(check_sorted(output.path(), None).expect("check"));
    }

    #[test]
    fn test_tmp_file_removed_after_external_sort() {
        // The external path writes a sibling scratch file; it must not survive.
        // Needs more than MIN_RUN_ENTRIES words so run generation makes >1 run
        // and a real merge (with a temp file) actually happens.
        let n = MIN_RUN_ENTRIES + 5000;
        let mut wordlist = NamedTempFile::new().expect("temp file");
        for i in 0..n {
            writeln!(wordlist, "word{i}").expect("write");
        }
        wordlist.flush().expect("flush");
        let output = NamedTempFile::new().expect("temp file");
        IndexBuilder::build(&Md5, wordlist.path(), output.path(), None).expect("build");

        // A tiny budget forces run generation to MIN_RUN_ENTRIES-sized runs, so
        // the file becomes two runs that must be merged through the scratch file.
        let mut sorter = IndexSorter::new(512 * ENTRY_SIZE);
        sorter.sort_file(output.path(), None).expect("sort failed");

        assert!(check_sorted(output.path(), None).expect("check"));
        assert!(
            !sort_tmp_path(output.path()).exists(),
            "scratch file must be cleaned up after sorting"
        );
    }
}
