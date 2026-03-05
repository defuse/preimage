use std::path::Path;

use anyhow::Result;

use crate::hashing::HashAlgorithm;
use crate::lookup::{LookupMatch, LookupTable};

/// A match from the oracle, wrapping a LookupMatch with table context.
pub struct OracleMatch<'a> {
    /// Which table produced this match (e.g. "md5-small").
    pub table_label: &'a str,
    /// The match itself (already contains the algorithm reference).
    pub lookup_match: LookupMatch<'a>,
}

/// Result for one queried hash across all tables.
pub struct HashResult<'a> {
    /// The hex hash that was queried.
    pub queried_hash: String,
    /// All matches found (may be empty if not cracked).
    pub matches: Vec<OracleMatch<'a>>,
}

/// Multi-table hash lookup oracle.
///
/// Register multiple `LookupTable`s and crack hashes against all of them.
pub struct PreimageOracle {
    tables: Vec<Table>,
}

struct Table {
    label: String,
    lookup: LookupTable,
}

impl PreimageOracle {
    pub fn new() -> Self {
        Self { tables: Vec::new() }
    }

    /// Register a lookup table. The algorithm type is passed directly
    /// (no Box needed in user code — type erasure is internal).
    pub fn register(
        &mut self,
        label: &str,
        algorithm: impl HashAlgorithm + 'static,
        index_path: &Path,
        dict_path: &Path,
    ) -> Result<()> {
        let lookup = LookupTable::open(algorithm, index_path, dict_path)?;
        self.tables.push(Table {
            label: label.to_string(),
            lookup,
        });
        Ok(())
    }

    /// Register a lookup table from a boxed algorithm (used by CLI code).
    pub fn register_boxed(
        &mut self,
        label: &str,
        algorithm: Box<dyn HashAlgorithm>,
        index_path: &Path,
        dict_path: &Path,
    ) -> Result<()> {
        let lookup = LookupTable::open_boxed(algorithm, index_path, dict_path)?;
        self.tables.push(Table {
            label: label.to_string(),
            lookup,
        });
        Ok(())
    }

    /// Crack multiple hashes against all registered tables.
    ///
    /// Iterates tables in registration order. For each table, tries ALL
    /// queried hashes before moving to the next table — this keeps the
    /// index mmap cache hot.
    ///
    /// If `early_exit` is true, a hash that already has a `Full` match
    /// is skipped for remaining tables.
    ///
    /// Returns results in the same order as the input hashes.
    pub fn crack<'a>(&'a self, hashes: &[&str], early_exit: bool) -> Vec<HashResult<'a>> {
        let mut results: Vec<HashResult<'a>> = hashes
            .iter()
            .map(|h| HashResult {
                queried_hash: h.to_string(),
                matches: Vec::new(),
            })
            .collect();

        for table in &self.tables {
            for (i, hash_hex) in hashes.iter().enumerate() {
                // Skip if early_exit and we already have a full match
                if early_exit && has_full_match(&results[i]) {
                    continue;
                }

                let lookup_matches = match table.lookup.lookup(hash_hex) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                for lm in lookup_matches {
                    results[i].matches.push(OracleMatch {
                        table_label: &table.label,
                        lookup_match: lm,
                    });
                }
            }
        }

        results
    }
}

fn has_full_match(result: &HashResult<'_>) -> bool {
    result
        .matches
        .iter()
        .any(|m| matches!(&m.lookup_match, LookupMatch::Full { .. }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::IndexBuilder;
    use crate::hashing::{Md5, Sha1};
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
        sorter.sort(index.path(), None).expect("sort");
        index
    }

    #[test]
    fn test_oracle_single_table() {
        let words = test_words_path();
        let idx = build_and_sort(&Md5, &words);

        let mut oracle = PreimageOracle::new();
        oracle
            .register("md5", Md5, idx.path(), &words)
            .expect("register");

        // MD5("apple") = 1f3870be274f6c49b3e31a0c6728957f
        let results = oracle.crack(&["1f3870be274f6c49b3e31a0c6728957f"], false);
        assert_eq!(results.len(), 1);
        assert!(!results[0].matches.is_empty());
        assert!(has_full_match(&results[0]));
    }

    #[test]
    fn test_oracle_multi_table() {
        let words = test_words_path();
        let md5_idx = build_and_sort(&Md5, &words);
        let sha1_idx = build_and_sort(&Sha1, &words);

        let mut oracle = PreimageOracle::new();
        oracle
            .register("md5", Md5, md5_idx.path(), &words)
            .expect("register md5");
        oracle
            .register("sha1", Sha1, sha1_idx.path(), &words)
            .expect("register sha1");

        // MD5("apple")
        let results = oracle.crack(&["1f3870be274f6c49b3e31a0c6728957f"], false);
        assert_eq!(results.len(), 1);
        let full: Vec<_> = results[0]
            .matches
            .iter()
            .filter(|m| matches!(&m.lookup_match, LookupMatch::Full { .. }))
            .collect();
        // Should find it in the md5 table (sha1 won't match this hash)
        assert_eq!(full.len(), 1);
        assert_eq!(full[0].table_label, "md5");
    }

    #[test]
    fn test_oracle_early_exit() {
        let words = test_words_path();
        let idx1 = build_and_sort(&Md5, &words);
        let idx2 = build_and_sort(&Md5, &words);

        let mut oracle = PreimageOracle::new();
        oracle
            .register("md5-first", Md5, idx1.path(), &words)
            .expect("register");
        oracle
            .register("md5-second", Md5, idx2.path(), &words)
            .expect("register");

        // With early_exit, should only find in first table
        let results = oracle.crack(&["1f3870be274f6c49b3e31a0c6728957f"], true);
        assert_eq!(results.len(), 1);
        let full: Vec<_> = results[0]
            .matches
            .iter()
            .filter(|m| matches!(&m.lookup_match, LookupMatch::Full { .. }))
            .collect();
        assert_eq!(full.len(), 1, "early_exit should stop after first full match");
        assert_eq!(full[0].table_label, "md5-first");
    }

    #[test]
    fn test_oracle_not_found() {
        let words = test_words_path();
        let idx = build_and_sort(&Md5, &words);

        let mut oracle = PreimageOracle::new();
        oracle
            .register("md5", Md5, idx.path(), &words)
            .expect("register");

        let results = oracle.crack(&["ffffffffffffffffffffffffffffffff"], false);
        assert_eq!(results.len(), 1);
        assert!(results[0].matches.is_empty());
    }

    #[test]
    fn test_oracle_batch() {
        let words = test_words_path();
        let idx = build_and_sort(&Md5, &words);

        let mut oracle = PreimageOracle::new();
        oracle
            .register("md5", Md5, idx.path(), &words)
            .expect("register");

        let results = oracle.crack(
            &[
                "1f3870be274f6c49b3e31a0c6728957f", // apple
                "ffffffffffffffffffffffffffffffff", // not found
                "5d41402abc4b2a76b9719d911017c592", // hello (not in words.txt)
            ],
            false,
        );
        assert_eq!(results.len(), 3);
        assert!(has_full_match(&results[0]), "apple should be found");
        assert!(results[1].matches.is_empty(), "bogus hash should not match");
    }
}
