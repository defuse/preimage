use std::path::Path;

use anyhow::{bail, Result};
use indicatif::ProgressBar;
use memmap2::Mmap;

use super::entry::IndexEntry;
use crate::HashAlgorithm;

impl super::IndexFile {
    /// Create a new index file from a wordlist and hash algorithm.
    ///
    /// Hashes every line in the wordlist, writing 14-byte entries
    /// (8-byte hash prefix + 6-byte LE wordlist position) to the output file.
    /// The resulting index is unsorted — call [`sort`](Self::sort) next.
    pub fn build(
        algorithm: &dyn HashAlgorithm,
        wordlist_path: &Path,
        output_path: &Path,
        progress: Option<&ProgressBar>,
    ) -> Result<Self> {
        IndexBuilder::build(algorithm, wordlist_path, output_path, progress)?;
        Ok(super::IndexFile {
            path: output_path.to_path_buf(),
        })
    }
}

pub(crate) struct IndexBuilder;

impl IndexBuilder {
    /// Create an unsorted index from a wordlist and hash algorithm.
    ///
    /// The wordlist is treated as raw bytes delimited by `\n` (0x0A).
    /// Words may contain arbitrary byte sequences — no UTF-8 assumption.
    ///
    /// For each line in the wordlist:
    /// 1. Record the byte position *before* reading the line
    /// 2. Strip trailing `\n` and `\r` bytes from the line
    /// 3. Hash the trimmed word
    /// 4. Write a 14-byte index entry (8-byte hash prefix + 6-byte LE position)
    ///
    /// Returns the number of entries written.
    pub fn build(
        algorithm: &dyn HashAlgorithm,
        wordlist_path: &Path,
        output_path: &Path,
        progress: Option<&ProgressBar>,
    ) -> Result<u64> {
        let wordlist = std::fs::File::open(wordlist_path)?;
        let file_len = wordlist.metadata()?.len();

        // `File::create` truncates, so if these two paths name the same file the wordlist
        // is destroyed before it is read and the build then "succeeds" with zero entries.
        // Refuse before creating the output.
        if is_same_file(wordlist_path, output_path) {
            bail!(
                "refusing to build: the output and the wordlist are the same file ({}). \
                 Building would truncate the wordlist before reading it.",
                output_path.display()
            );
        }

        let mut output = std::fs::File::create(output_path)?;

        if let Some(pb) = progress {
            pb.set_length(file_len);
        }

        // An empty wordlist has nothing to map or hash. `Mmap::map` also errors on a
        // zero-length file on some platforms, so handle it before mapping.
        if file_len == 0 {
            return Ok(0);
        }

        // SAFETY: `Mmap::map` requires that the file not be modified while mapped, by
        // anyone -- a concurrent truncation turns a read of the mapped pages into a
        // SIGBUS that cannot be caught. This code cannot establish that property; what
        // discharges it is the same deployment assumption the rest of the tool makes
        // (see `LookupTable::open` and the README's "Trust" section): the wordlist is
        // static data the operator owns and does not rewrite while a build runs.
        let mmap = unsafe { Mmap::map(&wordlist)? };
        let data: &[u8] = &mmap;
        let n = data.len();

        let threads = std::thread::available_parallelism()
            .map(|t| t.get())
            .unwrap_or(1);

        // Both parsing and hashing run in parallel. The file is processed in line-aligned
        // windows so the entries held in memory at once stay bounded; each window is split
        // into line-aligned sub-ranges, one per worker. A word's stored position is its
        // absolute byte offset, so the workers are independent and need no shared counter,
        // and concatenating their output in range order reproduces wordlist order exactly
        // -- the index is byte-identical to a serial build.
        let mut entries_written: u64 = 0;
        let mut wstart = 0usize;
        while wstart < n {
            let target = (wstart + WINDOW_BYTES).min(n);
            let wend = line_aligned_end(data, target);
            let ranges = split_into_line_aligned_ranges(data, wstart, wend, threads);

            let written = std::thread::scope(|scope| -> Result<u64> {
                let handles: Vec<_> = ranges
                    .iter()
                    .map(|&(start, end)| {
                        scope.spawn(move || process_range(algorithm, data, start, end))
                    })
                    .collect();

                let mut count = 0u64;
                for handle in handles {
                    let entries = handle.join().expect("hash worker panicked");
                    IndexEntry::write_bulk(&mut output, &entries, entries.len())?;
                    count += entries.len() as u64;
                }
                Ok(count)
            })?;

            entries_written += written;
            if let Some(pb) = progress {
                pb.set_position(wend as u64);
            }
            wstart = wend;
        }

        check_wordlist_was_fully_read(n as u64, file_len, wordlist_path)?;

        Ok(entries_written)
    }
}

/// How much input one window covers. Larger windows mean fewer synchronization points
/// between the parallel phase and the ordered write; smaller ones bound the entries
/// held in memory at once. Windows are line-aligned, so a single line longer than this
/// still ends up whole in one window.
const WINDOW_BYTES: usize = 128 << 20;

/// The offset just past the first `\n` at or after `target`, or the end of `data` if
/// there is none. Used to push a window or sub-range boundary onto a line boundary so
/// no line is ever split across workers.
fn line_aligned_end(data: &[u8], target: usize) -> usize {
    if target >= data.len() {
        return data.len();
    }
    match data[target..].iter().position(|&b| b == b'\n') {
        Some(rel) => target + rel + 1,
        None => data.len(),
    }
}

/// Split `[wstart, wend)` into `parts` contiguous ranges that each begin and end on a
/// line boundary, so every worker sees whole lines. `wstart` is already a line start
/// (the previous window ended after a `\n`, or it is 0). Ranges may be empty when there
/// are fewer lines than workers; the boundaries are clamped to stay non-decreasing and
/// within the window, so together they cover the window with no gaps or overlaps.
fn split_into_line_aligned_ranges(
    data: &[u8],
    wstart: usize,
    wend: usize,
    parts: usize,
) -> Vec<(usize, usize)> {
    let parts = parts.max(1);
    let span = wend - wstart;

    let mut bounds = Vec::with_capacity(parts + 1);
    bounds.push(wstart);
    for j in 1..parts {
        let target = wstart + span * j / parts;
        let prev = *bounds.last().expect("bounds is never empty");
        let b = line_aligned_end(data, target).min(wend).max(prev);
        bounds.push(b);
    }
    bounds.push(wend);

    bounds.windows(2).map(|w| (w[0], w[1])).collect()
}

/// Parse and hash every whole line in `data[start..end)`, returning the surviving
/// entries in order. `start` and `end` are line boundaries. A word's position is its
/// absolute offset `pos`, matching the serial builder, and words the algorithm rejects
/// simply produce no entry -- absolute positions make that need no bookkeeping.
///
/// `HashAlgorithm` is `Send + Sync`, so the one `&dyn` reference is shared across
/// workers as-is, reading straight from the memory-mapped wordlist with no copy.
fn process_range(
    algorithm: &dyn HashAlgorithm,
    data: &[u8],
    start: usize,
    end: usize,
) -> Vec<IndexEntry> {
    let mut entries = Vec::new();
    let mut pos = start;
    while pos < end {
        let (line_end, next) = match data[pos..end].iter().position(|&b| b == b'\n') {
            Some(rel) => (pos + rel, pos + rel + 1),
            // No terminator: only possible on the file's final line when it lacks one.
            None => (end, end),
        };

        // Both ends, matching PHP's trim($word, "\n\r") -- see the helper.
        let word = super::trim_record_separators(&data[pos..line_end]);
        if let Some(prefix) = hash_prefix(algorithm, word) {
            entries.push(IndexEntry::new(prefix, pos as u64));
        }
        pos = next;
    }
    entries
}

/// The 8-byte prefix stored for a word: the first 8 bytes of the digest, right-padded
/// with zeros for shorter digests. `None` if the algorithm rejects the word.
fn hash_prefix(algorithm: &dyn HashAlgorithm, word: &[u8]) -> Option<[u8; 8]> {
    let hash = algorithm.hash(word)?;
    let mut prefix = [0u8; 8];
    let copy_len = hash.len().min(8);
    prefix[..copy_len].copy_from_slice(&hash[..copy_len]);
    Some(prefix)
}

/// Fail if the builder read nothing from a wordlist that was not empty.
///
/// `bytes_read` counts every byte consumed, including lines the algorithm rejected, so
/// reading zero from a file whose metadata reported a non-zero length means the input
/// vanished underneath the builder — it was truncated between the `metadata` call and
/// the first read, and the index that was just written is silently empty.
///
/// This is deliberately keyed on bytes read rather than on entries written: a wordlist
/// whose every word the algorithm rejects legitimately produces zero entries, and
/// erroring on that would reject a correct build.
fn check_wordlist_was_fully_read(
    bytes_read: u64,
    file_len: u64,
    wordlist_path: &Path,
) -> Result<()> {
    if bytes_read == 0 && file_len > 0 {
        bail!(
            "read 0 bytes from {}, which metadata reported as {} bytes — the wordlist \
             was truncated while the index was being built",
            wordlist_path.display(),
            file_len
        );
    }
    Ok(())
}

/// Whether two paths lead to the same file on disk.
///
/// `canonicalize` resolves `.`, `..` and symlinks, so it catches the ordinary aliases
/// (`words.txt` vs `./words.txt`, or an output symlinked onto the input). On Unix the
/// device and inode are compared as well, which additionally catches a hard link. The
/// output normally does not exist yet, and a path that cannot be canonicalized cannot be
/// an alias of one that can, so failures are answered "not the same file" rather than
/// propagated.
fn is_same_file(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(a_meta), Ok(b_meta)) = (std::fs::metadata(a), std::fs::metadata(b)) {
            if a_meta.dev() == b_meta.dev() && a_meta.ino() == b_meta.ino() {
                return true;
            }
        }
    }

    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::ENTRY_SIZE;
    use crate::{Md5, Ntlm};
    use tempfile::NamedTempFile;

    fn test_words_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("test_data")
            .join("words.txt")
    }

    #[test]
    fn test_build_creates_valid_index() {
        let output = NamedTempFile::new().expect("failed to create temp file");
        let count = IndexBuilder::build(&Md5, &test_words_path(), output.path(), None)
            .expect("build failed");

        assert!(count > 0, "should write at least one entry");

        let file_len = std::fs::metadata(output.path()).expect("metadata").len();
        assert_eq!(
            file_len,
            count * ENTRY_SIZE as u64,
            "file size should be entry_count * ENTRY_SIZE"
        );
    }

    #[test]
    fn test_build_positions_match_byte_offsets() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        use std::io::Write;
        // "apple\nbanana\n" — apple starts at 0, banana starts at 6
        write!(wordlist, "apple\nbanana\n").expect("write");

        let output = NamedTempFile::new().expect("temp file");
        let count =
            IndexBuilder::build(&Md5, wordlist.path(), output.path(), None).expect("build failed");
        assert_eq!(count, 2);

        let data = std::fs::read(output.path()).expect("read");
        let entry0 = IndexEntry::read_from(&mut &data[0..ENTRY_SIZE]).expect("read entry");
        let entry1 =
            IndexEntry::read_from(&mut &data[ENTRY_SIZE..2 * ENTRY_SIZE]).expect("read entry");

        assert_eq!(entry0.position(), 0, "apple should be at position 0");
        assert_eq!(entry1.position(), 6, "banana should be at position 6");
    }

    #[test]
    fn test_build_hash_prefix_matches() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        use std::io::Write;
        write!(wordlist, "hello\n").expect("write");

        let output = NamedTempFile::new().expect("temp file");
        IndexBuilder::build(&Md5, wordlist.path(), output.path(), None).expect("build failed");

        let data = std::fs::read(output.path()).expect("read");
        let entry = IndexEntry::read_from(&mut &data[..]).expect("read entry");

        // MD5("hello") = 5d41402abc4b2a76b9719d911017c592
        // First 8 bytes: 5d41402abc4b2a76
        let expected_prefix: [u8; 8] = [0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76];
        assert_eq!(entry.hash_prefix, expected_prefix);
    }

    #[test]
    fn test_build_handles_non_utf8_words() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        use std::io::Write;
        // Write binary data: 0xFF 0xFE (invalid UTF-8) followed by newline
        wordlist.write_all(&[0xFF, 0xFE, b'\n']).expect("write");
        // Then a normal word
        wordlist.write_all(b"hello\n").expect("write");

        let output = NamedTempFile::new().expect("temp file");
        let count = IndexBuilder::build(&Md5, wordlist.path(), output.path(), None)
            .expect("build should not fail on non-UTF-8 data");
        assert_eq!(count, 2, "both lines should produce entries");

        // Verify first entry hashes the raw bytes [0xFF, 0xFE]
        let data = std::fs::read(output.path()).expect("read");
        let entry0 = IndexEntry::read_from(&mut &data[0..ENTRY_SIZE]).expect("read entry");

        let expected_hash = Md5.hash(&[0xFF, 0xFE]).expect("md5 should hash any bytes");
        let mut expected_prefix = [0u8; 8];
        expected_prefix.copy_from_slice(&expected_hash[..8]);
        assert_eq!(entry0.hash_prefix, expected_prefix);
    }

    /// A line beginning with `\r` must be indexed as the word without it, the way
    /// createidx.php's two-sided `trim($word, "\n\r")` does. The builder hashes the
    /// trimmed word, so this asserts on the digest actually written to the index --
    /// with the old one-sided trim it was MD5("\rletmein") and the word was
    /// unreachable through a Rust-built index.
    #[test]
    fn test_leading_carriage_return_is_stripped_like_php_trim() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        use std::io::Write;
        // Line 2 begins with \r; line 3 has leading spaces that must survive.
        wordlist
            .write_all(b"apple\n\rletmein\n  spaced  \n")
            .expect("write");
        wordlist.flush().expect("flush");

        let output = NamedTempFile::new().expect("temp file");
        let entries = IndexBuilder::build(&Md5, wordlist.path(), output.path(), None)
            .expect("build must succeed");
        assert_eq!(entries, 3);

        let index = std::fs::read(output.path()).expect("read index");
        let prefix_at = |n: usize| index[n * ENTRY_SIZE..n * ENTRY_SIZE + 8].to_vec();

        let expect = |word: &str| Md5.hash(word.as_bytes()).expect("md5")[..8].to_vec();

        assert_eq!(prefix_at(0), expect("apple"));
        assert_eq!(
            prefix_at(1),
            expect("letmein"),
            "a leading \\r must be stripped, matching createidx.php"
        );
        assert_ne!(
            prefix_at(1),
            expect("\rletmein"),
            "the untrimmed form must not be what got indexed"
        );
        assert_eq!(
            prefix_at(2),
            expect("  spaced  "),
            "spaces are password bytes and must survive the trim"
        );
    }

    /// Building an index onto its own wordlist truncates the wordlist before a single
    /// byte has been read, and then reports success with zero entries. Refuse instead.
    #[test]
    fn test_build_refuses_to_write_over_its_own_wordlist() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        use std::io::Write;
        write!(wordlist, "apple\nbanana\n").expect("write");
        wordlist.flush().expect("flush");

        let error = IndexBuilder::build(&Md5, wordlist.path(), wordlist.path(), None)
            .expect_err("building onto the wordlist must fail");
        assert!(
            error.to_string().contains("the same file"),
            "unexpected error: {error}"
        );

        assert_eq!(
            std::fs::read(wordlist.path()).expect("read"),
            b"apple\nbanana\n".to_vec(),
            "the wordlist must be untouched"
        );
    }

    /// Reading nothing from a non-empty wordlist means it was truncated mid-build, and
    /// the index just written is silently empty. That state cannot be produced through
    /// the public API without racing the builder, so the check is asserted directly.
    #[test]
    fn test_truncated_wordlist_is_an_error_but_a_fully_rejected_one_is_not() {
        let path = Path::new("words.txt");

        let error = check_wordlist_was_fully_read(0, 4096, path)
            .expect_err("reading 0 bytes from a 4096-byte file must fail");
        assert_eq!(
            error.to_string(),
            "read 0 bytes from words.txt, which metadata reported as 4096 bytes — \
             the wordlist was truncated while the index was being built"
        );

        // An empty wordlist read as empty is consistent, not a truncation.
        check_wordlist_was_fully_read(0, 0, path).expect("an empty wordlist is not an error");
        // Every byte read, even if every word was rejected and no entry was written.
        check_wordlist_was_fully_read(4096, 4096, path).expect("a fully read wordlist is fine");
        check_wordlist_was_fully_read(1, 4096, path)
            .expect("a partial read is not what this check is for");
    }

    /// The companion property, through the public API: a wordlist the algorithm rejects
    /// in its entirety builds a legitimate empty index rather than tripping the guard.
    /// NTLM rejects non-UTF-8 input, so every line here is skipped.
    #[test]
    fn test_wordlist_rejected_in_its_entirety_builds_an_empty_index() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        use std::io::Write;
        wordlist
            .write_all(b"\xff\xfe\n\xff\xfe\xfd\n")
            .expect("write");
        wordlist.flush().expect("flush");

        let output = NamedTempFile::new().expect("temp file");
        let entries = IndexBuilder::build(&Ntlm, wordlist.path(), output.path(), None)
            .expect("a fully rejected wordlist must still build");

        assert_eq!(entries, 0);
        assert_eq!(
            std::fs::metadata(output.path())
                .expect("index must exist")
                .len(),
            0
        );
    }

    /// The alias does not have to be the identical path string: a symlink resolves to the
    /// same file, and a hard link is the same inode without resolving to the same path.
    #[cfg(unix)]
    #[test]
    fn test_build_refuses_an_output_that_is_a_link_to_the_wordlist() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wordlist_path = dir.path().join("words.txt");
        std::fs::write(&wordlist_path, b"apple\nbanana\n").expect("write wordlist");

        let symlinked = dir.path().join("symlinked.idx");
        std::os::unix::fs::symlink(&wordlist_path, &symlinked).expect("symlink");

        let hardlinked = dir.path().join("hardlinked.idx");
        std::fs::hard_link(&wordlist_path, &hardlinked).expect("hard link");

        for output_path in [&symlinked, &hardlinked] {
            let error = IndexBuilder::build(&Md5, &wordlist_path, output_path, None)
                .expect_err("building onto a link to the wordlist must fail");
            assert!(
                error.to_string().contains("the same file"),
                "unexpected error for {}: {error}",
                output_path.display()
            );
            assert_eq!(
                std::fs::read(&wordlist_path).expect("read"),
                b"apple\nbanana\n".to_vec(),
                "the wordlist must survive {}",
                output_path.display()
            );
        }
    }

    /// Words the algorithm rejects must be omitted from the index entirely, and
    /// must still advance the wordlist position — otherwise every entry after a
    /// rejected word points at the wrong offset. This is the CrackStation bug
    /// where invalid NTLM input was indexed as the hash of the empty string.
    #[test]
    fn test_build_skips_words_the_algorithm_rejects() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        use std::io::Write;
        // 0xFF 0xFE is not valid UTF-8, so NTLM rejects it. 3 bytes with the \n.
        wordlist.write_all(&[0xFF, 0xFE, b'\n']).expect("write");
        wordlist.write_all(b"hello\n").expect("write");
        wordlist.flush().expect("flush");

        let output = NamedTempFile::new().expect("temp file");
        let count =
            IndexBuilder::build(&Ntlm, wordlist.path(), output.path(), None).expect("build failed");

        assert_eq!(count, 1, "the rejected word must not produce an entry");

        let data = std::fs::read(output.path()).expect("read");
        assert_eq!(data.len(), ENTRY_SIZE, "index must hold exactly one entry");

        let entry = IndexEntry::read_from(&mut &data[..]).expect("read entry");

        // "hello" starts at byte 3, after the 3-byte rejected line. A skip that
        // forgot to advance the position would leave this at 0.
        assert_eq!(entry.position(), 3);

        let expected_hash = Ntlm.hash(b"hello").expect("ntlm should hash ascii");
        let mut expected_prefix = [0u8; 8];
        expected_prefix.copy_from_slice(&expected_hash[..8]);
        assert_eq!(entry.hash_prefix, expected_prefix);
    }

    /// An independent, dead-simple serial reference: split on `\n`, trim `\n\r` from
    /// both ends, hash, and record `(line-start offset, 8-byte prefix)` for each word
    /// the algorithm accepts. Deliberately not the builder's own helpers, so it checks
    /// the parallel path against something, not against itself.
    fn serial_reference(data: &[u8], alg: &dyn crate::HashAlgorithm) -> Vec<(u64, [u8; 8])> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos < data.len() {
            let (line_end, next) = match data[pos..].iter().position(|&b| b == b'\n') {
                Some(rel) => (pos + rel, pos + rel + 1),
                None => (data.len(), data.len()),
            };
            let mut word = &data[pos..line_end];
            while matches!(word.last(), Some(b'\n' | b'\r')) {
                word = &word[..word.len() - 1];
            }
            while matches!(word.first(), Some(b'\n' | b'\r')) {
                word = &word[1..];
            }
            if let Some(hash) = alg.hash(word) {
                let mut prefix = [0u8; 8];
                let c = hash.len().min(8);
                prefix[..c].copy_from_slice(&hash[..c]);
                out.push((pos as u64, prefix));
            }
            pos = next;
        }
        out
    }

    fn read_index(path: &Path) -> Vec<(u64, [u8; 8])> {
        let data = std::fs::read(path).expect("read index");
        assert_eq!(data.len() % ENTRY_SIZE, 0);
        data.chunks_exact(ENTRY_SIZE)
            .map(|c| {
                let e = IndexEntry::read_from(&mut &c[..]).expect("entry");
                (e.position(), e.hash_prefix)
            })
            .collect()
    }

    /// The parallel, windowed, memory-mapped build must match the serial reference
    /// exactly -- same entries, same order, same positions -- across many lines (so the
    /// input is split among several workers) with a mix of plain words, CRLF endings,
    /// leading/trailing spaces, empty lines, invalid UTF-8 (which NTLM rejects but MD5
    /// keeps), and a final line with no terminator.
    #[test]
    fn test_parallel_build_matches_serial_reference() {
        use std::io::Write;
        let mut data = Vec::new();
        for i in 0..60_000u32 {
            match i % 7 {
                0 => data.extend_from_slice(format!("word{i}\n").as_bytes()),
                1 => data.extend_from_slice(format!("pass{i}\r\n").as_bytes()),
                2 => data.push(b'\n'),
                3 => {
                    data.extend_from_slice(&[0xff, 0xfe]);
                    data.push(b'\n');
                }
                4 => data.extend_from_slice(format!("  spaced{i}  \n").as_bytes()),
                5 => data.extend_from_slice(format!("{i}\n").as_bytes()),
                _ => data.extend_from_slice(format!("user{i}@example.com\n").as_bytes()),
            }
        }
        data.extend_from_slice(b"tail-with-no-newline");

        let mut wordlist = NamedTempFile::new().expect("temp file");
        wordlist.write_all(&data).expect("write");
        wordlist.flush().expect("flush");

        for alg in [
            &Md5 as &dyn crate::HashAlgorithm,
            &Ntlm as &dyn crate::HashAlgorithm,
        ] {
            let output = NamedTempFile::new().expect("temp file");
            let count = IndexBuilder::build(alg, wordlist.path(), output.path(), None)
                .expect("build failed");

            let expected = serial_reference(&data, alg);
            assert_eq!(
                count as usize,
                expected.len(),
                "{}: entry count must match the serial reference",
                alg.name()
            );
            assert_eq!(
                read_index(output.path()),
                expected,
                "{}: parallel build must match the serial reference byte-for-byte",
                alg.name()
            );
        }
    }
}
