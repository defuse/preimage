use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use anyhow::Result;
use indicatif::ProgressBar;

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
        let mut reader = BufReader::new(wordlist);

        let output = std::fs::File::create(output_path)?;
        let mut writer = BufWriter::new(output);

        if let Some(pb) = progress {
            pb.set_length(file_len);
        }

        let mut entries_written: u64 = 0;
        let mut position: u64 = 0;
        let mut line_buf = Vec::new();

        loop {
            line_buf.clear();
            let bytes_read = reader.read_until(b'\n', &mut line_buf)?;
            if bytes_read == 0 {
                break;
            }

            // Strip trailing \n and \r, matching PHP's trim($word, "\n\r")
            let mut word = &line_buf[..];
            while word.last() == Some(&b'\n') || word.last() == Some(&b'\r') {
                word = &word[..word.len() - 1];
            }

            let hash = match algorithm.hash(word) {
                Some(h) => h,
                None => {
                    // Skip words that the algorithm rejects (e.g. NTLM on invalid UTF-8)
                    position += bytes_read as u64;
                    if let Some(pb) = progress {
                        pb.set_position(position);
                    }
                    continue;
                }
            };

            // Take first 8 bytes, right-pad with zeros if shorter
            let mut hash_prefix = [0u8; 8];
            let copy_len = hash.len().min(8);
            hash_prefix[..copy_len].copy_from_slice(&hash[..copy_len]);

            let entry = IndexEntry::new(hash_prefix, position);
            entry.write_to(&mut writer)?;

            entries_written += 1;
            position += bytes_read as u64;

            if let Some(pb) = progress {
                pb.set_position(position);
            }
        }

        writer.flush()?;
        Ok(entries_written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::ENTRY_SIZE;
    use crate::Md5;
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
}
