use std::path::{Path, PathBuf};

pub(crate) mod builder;
pub(crate) mod checker;
pub mod entry;
pub mod lookup;
pub(crate) mod sorter;

/// Strip record separators from a wordlist line, reproducing `createidx.php`'s
/// `trim($word, "\n\r")`.
///
/// PHP's `trim` with a character set is **two-sided** — the argument restricts which
/// characters are stripped, not which end they are stripped from; `ltrim`/`rtrim` are
/// the one-sided variants. Only `\n` and `\r` are removed: leading and trailing spaces
/// and tabs are part of the password and must survive.
///
/// The builder and the lookup path must agree on this exactly. The builder hashes the
/// trimmed word but stores the offset of the *line*, so the lookup re-reads from that
/// offset and re-trims before re-hashing; if the two trims disagreed, an index would
/// fail to verify its own entries and every affected word would report "not found".
pub(crate) fn trim_record_separators(line: &[u8]) -> &[u8] {
    let mut word = line;
    while matches!(word.last(), Some(b'\n' | b'\r')) {
        word = &word[..word.len() - 1];
    }
    while matches!(word.first(), Some(b'\n' | b'\r')) {
        word = &word[1..];
    }
    word
}

#[cfg(test)]
mod trim_tests {
    use super::trim_record_separators;

    /// PHP's trim is two-sided. The Rust port originally stripped only the end, so a
    /// line beginning with `\r` was indexed as `\rword` while createidx.php indexed
    /// `word` -- the word became uncrackable through a Rust-built index.
    #[test]
    fn strips_newlines_and_carriage_returns_from_both_ends() {
        assert_eq!(trim_record_separators(b"\rletmein\n"), b"letmein");
        assert_eq!(trim_record_separators(b"\r\nletmein\r\n"), b"letmein");
        assert_eq!(trim_record_separators(b"letmein\r\n"), b"letmein");
        assert_eq!(trim_record_separators(b"\n\r\rletmein"), b"letmein");
    }

    /// Only `\n` and `\r`. Spaces and tabs are significant password bytes.
    #[test]
    fn preserves_spaces_and_tabs_at_both_ends() {
        assert_eq!(trim_record_separators(b" letmein \n"), b" letmein ");
        assert_eq!(trim_record_separators(b"\r\tletmein\t\r"), b"\tletmein\t");
        assert_eq!(trim_record_separators(b"  \n"), b"  ");
    }

    #[test]
    fn handles_empty_and_separator_only_lines() {
        assert_eq!(trim_record_separators(b""), b"");
        assert_eq!(trim_record_separators(b"\n"), b"");
        assert_eq!(trim_record_separators(b"\r\n"), b"");
        assert_eq!(trim_record_separators(b"\r\r\n\n"), b"");
    }

    /// Interior separators are not touched -- only the ends.
    #[test]
    fn leaves_interior_bytes_alone() {
        assert_eq!(trim_record_separators(b"\rlet\rmein\n"), b"let\rmein");
    }
}

/// An index file on disk mapping hash prefixes to wordlist positions.
///
/// This is the main entry point for the library. Use it to build, sort,
/// verify, and look up hashes against an index.
pub struct IndexFile {
    path: PathBuf,
}

impl IndexFile {
    /// Reference an existing index file at the given path.
    pub fn open(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Get the path to the index file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Count the number of entries in the index file.
    pub fn entry_count(&self) -> anyhow::Result<u64> {
        let size = std::fs::metadata(&self.path)?.len();
        if size % entry::ENTRY_SIZE as u64 != 0 {
            anyhow::bail!(
                "index file size {} is not a multiple of entry size {}",
                size,
                entry::ENTRY_SIZE
            );
        }
        Ok(size / entry::ENTRY_SIZE as u64)
    }
}
