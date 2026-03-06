use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use memmap2::Mmap;

use crate::entry::{decode_position, ENTRY_SIZE, HASH_PREFIX_LEN, POSITION_LEN};
use crate::hashing::HashAlgorithm;

/// A match from looking up one hash against one index.
pub enum LookupMatch<'a> {
    /// All bytes of the recomputed hash match the queried hash.
    Full {
        /// The raw plaintext bytes from the wordlist.
        plaintext: Vec<u8>,
        recomputed_hash: Vec<u8>,
        algorithm: &'a dyn HashAlgorithm,
    },
    /// Only the 8-byte prefix matched; full hash differs.
    Partial {
        /// The raw plaintext bytes from the wordlist.
        plaintext: Vec<u8>,
        recomputed_hash: Vec<u8>,
        algorithm: &'a dyn HashAlgorithm,
    },
}

impl<'a> LookupMatch<'a> {
    /// Get the plaintext bytes regardless of match type.
    pub fn plaintext(&self) -> &[u8] {
        match self {
            LookupMatch::Full { plaintext, .. } => plaintext,
            LookupMatch::Partial { plaintext, .. } => plaintext,
        }
    }

    /// Get the plaintext as a lossy UTF-8 string (for display).
    pub fn plaintext_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(self.plaintext())
    }

    /// Get the recomputed full hash bytes.
    pub fn recomputed_hash(&self) -> &[u8] {
        match self {
            LookupMatch::Full { recomputed_hash, .. } => recomputed_hash,
            LookupMatch::Partial { recomputed_hash, .. } => recomputed_hash,
        }
    }

    /// Get the algorithm that produced this match.
    pub fn algorithm(&self) -> &'a dyn HashAlgorithm {
        match self {
            LookupMatch::Full { algorithm, .. } => *algorithm,
            LookupMatch::Partial { algorithm, .. } => *algorithm,
        }
    }

    /// Returns true if this is a full match.
    pub fn is_full(&self) -> bool {
        matches!(self, LookupMatch::Full { .. })
    }
}

impl crate::IndexFile {
    /// Open the index for hash lookups, consuming the `IndexFile`.
    ///
    /// The index must be sorted. The dictionary is the wordlist used to
    /// create the index.
    pub fn into_lookup_table(
        self,
        algorithm: impl HashAlgorithm + 'static,
        dict_path: &Path,
    ) -> Result<LookupTable> {
        LookupTable::open(algorithm, &self.path, dict_path)
    }
}

/// An mmap-backed sorted index for hash lookups.
pub struct LookupTable {
    algorithm: Box<dyn HashAlgorithm>,
    index_mmap: Mmap,
    dict_path: PathBuf,
    entry_count: u64,
}

impl LookupTable {
    /// Open a lookup table.
    ///
    /// The index file must be sorted. The dictionary file is the original
    /// wordlist used to create the index.
    ///
    /// Accepts any `HashAlgorithm` implementor, including `Box<dyn HashAlgorithm>`.
    pub(crate) fn open(
        algorithm: impl HashAlgorithm + 'static,
        index_path: &Path,
        dict_path: &Path,
    ) -> Result<Self> {
        let index_file = File::open(index_path)?;
        let file_size = index_file.metadata()?.len();

        if file_size % ENTRY_SIZE as u64 != 0 {
            bail!(
                "index file size {} is not a multiple of entry size {}",
                file_size,
                ENTRY_SIZE
            );
        }

        let entry_count = file_size / ENTRY_SIZE as u64;

        // SAFETY: memmap2::Mmap::map requires the file not be modified while mapped.
        // We open the index read-only and never modify it.
        let index_mmap = unsafe { Mmap::map(&index_file)? };

        Ok(Self {
            algorithm: Box::new(algorithm),
            index_mmap,
            dict_path: dict_path.to_path_buf(),
            entry_count,
        })
    }

    /// Access the algorithm this table uses.
    pub fn algorithm(&self) -> &dyn HashAlgorithm {
        &*self.algorithm
    }

    /// Look up a hex-encoded hash. Returns all prefix matches.
    pub fn lookup(&self, hash_hex: &str) -> Result<Vec<LookupMatch<'_>>> {
        let hash_bytes = parse_hash_hex(hash_hex)?;

        if self.entry_count == 0 {
            return Ok(Vec::new());
        }

        // Extract the 8-byte search prefix
        let mut search_prefix = [0u8; HASH_PREFIX_LEN];
        let copy_len = hash_bytes.len().min(HASH_PREFIX_LEN);
        search_prefix[..copy_len].copy_from_slice(&hash_bytes[..copy_len]);

        // Binary search over mmap'd entries
        let find = self.binary_search(&search_prefix);

        let Some(mut idx) = find else {
            return Ok(Vec::new());
        };

        // Walk backward to find start of collision block
        while idx > 0 && self.get_entry_prefix(idx - 1) == search_prefix {
            idx -= 1;
        }

        // Walk forward through collision block, collecting matches
        let mut results = Vec::new();
        let mut dict_file = File::open(&self.dict_path)?;

        while idx < self.entry_count && self.get_entry_prefix(idx) == search_prefix {
            let position = self.get_entry_position(idx);
            let word = read_word_at(&mut dict_file, position)?;

            if let Some(recomputed) = self.algorithm.hash(&word) {
                if recomputed == hash_bytes {
                    results.push(LookupMatch::Full {
                        plaintext: word,
                        recomputed_hash: recomputed,
                        algorithm: &*self.algorithm,
                    });
                } else {
                    results.push(LookupMatch::Partial {
                        plaintext: word,
                        recomputed_hash: recomputed,
                        algorithm: &*self.algorithm,
                    });
                }
            }

            idx += 1;
        }

        Ok(results)
    }

    /// Binary search for a hash prefix. Returns `Some(index)` of a matching entry,
    /// or `None` if not found.
    fn binary_search(&self, target: &[u8; HASH_PREFIX_LEN]) -> Option<u64> {
        let mut lower: i64 = 0;
        let mut upper: i64 = self.entry_count as i64 - 1;

        while upper >= lower {
            let middle = lower + (upper - lower) / 2;
            let prefix = self.get_entry_prefix(middle as u64);

            match prefix.cmp(target) {
                std::cmp::Ordering::Greater => upper = middle - 1,
                std::cmp::Ordering::Less => lower = middle + 1,
                std::cmp::Ordering::Equal => return Some(middle as u64),
            }
        }

        None
    }

    /// Read the 8-byte hash prefix of an entry directly from the mmap.
    fn get_entry_prefix(&self, index: u64) -> [u8; HASH_PREFIX_LEN] {
        let offset = index as usize * ENTRY_SIZE;
        let mut prefix = [0u8; HASH_PREFIX_LEN];
        prefix.copy_from_slice(&self.index_mmap[offset..offset + HASH_PREFIX_LEN]);
        prefix
    }

    /// Read the 48-bit LE position of an entry directly from the mmap.
    fn get_entry_position(&self, index: u64) -> u64 {
        let offset = index as usize * ENTRY_SIZE + HASH_PREFIX_LEN;
        let bytes: &[u8; POSITION_LEN] = self.index_mmap[offset..offset + POSITION_LEN]
            .try_into()
            .expect("slice is exactly POSITION_LEN bytes");
        decode_position(bytes)
    }
}

/// Parse a hex-encoded hash string into raw bytes.
pub(crate) fn parse_hash_hex(hash_hex: &str) -> Result<Vec<u8>> {
    if hash_hex.len() % 2 != 0 {
        bail!("hash hex string has odd length");
    }
    if hash_hex.len() < HASH_PREFIX_LEN * 2 {
        bail!(
            "hash hex string too short (need at least {} hex chars, got {})",
            HASH_PREFIX_LEN * 2,
            hash_hex.len()
        );
    }
    let bytes = hex::decode(hash_hex)?;
    Ok(bytes)
}

/// Read a word from the dictionary file at the given byte position.
///
/// Reads raw bytes until `\n` (0x0A), then strips trailing `\n` and `\r`.
/// Matching PHP's `trim($word)` in LookupTable.php — which strips all
/// leading/trailing whitespace. However, `createidx.php` uses
/// `trim($word, "\n\r")` which only strips newlines. We match the index
/// creation behavior (strip only `\n`/`\r`) since that's what determines
/// which bytes get hashed.
fn read_word_at(file: &mut File, position: u64) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(position))?;
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    reader.read_until(b'\n', &mut line)?;
    // Strip trailing \n and \r, matching PHP's trim($word, "\n\r") in createidx.php
    while line.last() == Some(&b'\n') || line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::IndexBuilder;
    use crate::hashing::Md5;
    use crate::sorter::IndexSorter;
    use tempfile::NamedTempFile;

    fn test_words_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("test_data")
            .join("words.txt")
    }

    fn build_and_sort(algorithm: &dyn HashAlgorithm, wordlist: &Path) -> NamedTempFile {
        let index = NamedTempFile::new().expect("temp file");
        IndexBuilder::build(algorithm, wordlist, index.path(), None).expect("build");
        let mut sorter = IndexSorter::new(1);
        sorter.sort_file(index.path(), None).expect("sort");
        index
    }

    #[test]
    fn test_lookup_known_hash() {
        // "hello" -> MD5 = 5d41402abc4b2a76b9719d911017c592
        let mut wordlist = NamedTempFile::new().expect("temp file");
        std::io::Write::write_all(&mut wordlist, b"hello\n").expect("write");

        let index = build_and_sort(&Md5, wordlist.path());
        let table = LookupTable::open(Md5, index.path(), wordlist.path()).expect("open");

        let matches = table
            .lookup("5d41402abc4b2a76b9719d911017c592")
            .expect("lookup");
        assert_eq!(matches.len(), 1);
        assert!(matches[0].is_full());
        assert_eq!(matches[0].plaintext(), b"hello");
    }

    #[test]
    fn test_lookup_not_found() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        std::io::Write::write_all(&mut wordlist, b"hello\n").expect("write");

        let index = build_and_sort(&Md5, wordlist.path());
        let table = LookupTable::open(Md5, index.path(), wordlist.path()).expect("open");

        let matches = table
            .lookup("ffffffffffffffffffffffffffffffff")
            .expect("lookup");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_lookup_from_test_words() {
        let index = build_and_sort(&Md5, &test_words_path());
        let table =
            LookupTable::open(Md5, index.path(), &test_words_path()).expect("open");

        // MD5("apple") = 1f3870be274f6c49b3e31a0c6728957f
        let matches = table
            .lookup("1f3870be274f6c49b3e31a0c6728957f")
            .expect("lookup");
        let full_matches: Vec<_> = matches.iter().filter(|m| m.is_full()).collect();
        assert_eq!(full_matches.len(), 1);
        assert_eq!(full_matches[0].plaintext(), b"apple");
    }

    #[test]
    fn test_lookup_invalid_hex() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        std::io::Write::write_all(&mut wordlist, b"hello\n").expect("write");
        let index = build_and_sort(&Md5, wordlist.path());
        let table = LookupTable::open(Md5, index.path(), wordlist.path()).expect("open");

        assert!(table.lookup("xyz").is_err());
        assert!(table.lookup("5d4140").is_err()); // too short
    }

    #[test]
    fn test_lookup_empty_index() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        std::io::Write::write_all(&mut wordlist, b"").expect("write");
        let index = build_and_sort(&Md5, wordlist.path());
        let table = LookupTable::open(Md5, index.path(), wordlist.path()).expect("open");

        let matches = table
            .lookup("5d41402abc4b2a76b9719d911017c592")
            .expect("lookup");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_lookup_non_utf8_word() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        // Write binary word: [0xFF, 0xFE] then newline
        std::io::Write::write_all(&mut wordlist, &[0xFF, 0xFE, b'\n']).expect("write");

        let index = build_and_sort(&Md5, wordlist.path());
        let table = LookupTable::open(Md5, index.path(), wordlist.path()).expect("open");

        // MD5 of raw bytes [0xFF, 0xFE]
        let hash = hex::encode(Md5.hash(&[0xFF, 0xFE]).expect("md5"));
        let matches = table.lookup(&hash).expect("lookup");
        assert_eq!(matches.len(), 1);
        assert!(matches[0].is_full());
        assert_eq!(matches[0].plaintext(), &[0xFF, 0xFE]);
    }
}
