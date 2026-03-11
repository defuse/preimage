use std::path::Path;

use anyhow::Result;

use crate::HashAlgorithm;
use crate::index::lookup::{parse_hash_hex, LookupMatch, LookupTable};

/// A match from the oracle, wrapping a LookupMatch with table context.
pub struct OracleMatch<'a> {
    /// Which table produced this match (e.g. "md5-small").
    pub table_label: &'a str,
    /// The match itself (already contains the algorithm reference).
    pub lookup_match: LookupMatch,
}

/// Result for one queried hash across all tables.
pub enum HashResult<'a> {
    /// The input was a valid hex hash; matches may be empty (not found).
    Lookup {
        queried_hash: String,
        matches: Vec<OracleMatch<'a>>,
    },
    /// The input was not a valid hash format (non-hex, odd-length, or too short).
    InvalidFormat {
        input: String,
    },
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

    /// Register a lookup table.
    pub fn register(
        &mut self,
        label: &str,
        algorithm: &'static dyn HashAlgorithm,
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
        // Validate all hashes upfront. Invalid ones get InvalidFormat immediately.
        let mut results: Vec<HashResult<'a>> = hashes
            .iter()
            .map(|h| {
                if parse_hash_hex(h).is_ok() {
                    HashResult::Lookup {
                        queried_hash: h.to_string(),
                        matches: Vec::new(),
                    }
                } else {
                    HashResult::InvalidFormat {
                        input: h.to_string(),
                    }
                }
            })
            .collect();

        for table in &self.tables {
            for (i, hash_hex) in hashes.iter().enumerate() {
                // Skip invalid hashes entirely
                let HashResult::Lookup { matches, .. } = &mut results[i] else {
                    continue;
                };

                // Skip if early_exit and we already have a full match
                if early_exit && has_full_match_in(matches) {
                    continue;
                }

                let lookup_matches = match table.lookup.lookup(hash_hex) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                for lm in lookup_matches {
                    matches.push(OracleMatch {
                        table_label: &table.label,
                        lookup_match: lm,
                    });
                }
            }
        }

        results
    }
}

/// Check if a matches vec already contains a full match (used in crack loop).
fn has_full_match_in(matches: &[OracleMatch<'_>]) -> bool {
    matches
        .iter()
        .any(|m| matches!(&m.lookup_match, LookupMatch::Full { .. }))
}

/// Check if a HashResult has a full match (used in tests).
#[cfg(test)]
fn has_full_match(result: &HashResult<'_>) -> bool {
    match result {
        HashResult::Lookup { matches, .. } => has_full_match_in(matches),
        HashResult::InvalidFormat { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::builder::IndexBuilder;
    use crate::{MD5, SHA1, Md5, Sha1};
    use crate::index::sorter::IndexSorter;
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
        let mut sorter = IndexSorter::new(1024 * 1024);
        sorter.sort_file(index.path(), None).expect("sort");
        index
    }

    #[test]
    fn test_oracle_single_table() {
        let words = test_words_path();
        let idx = build_and_sort(&Md5, &words);

        let mut oracle = PreimageOracle::new();
        oracle
            .register("md5", MD5, idx.path(), &words)
            .expect("register");

        // MD5("apple") = 1f3870be274f6c49b3e31a0c6728957f
        let results = oracle.crack(&["1f3870be274f6c49b3e31a0c6728957f"], false);
        assert_eq!(results.len(), 1);
        let HashResult::Lookup { matches, .. } = &results[0] else {
            panic!("expected Lookup variant");
        };
        assert!(!matches.is_empty());
        assert!(has_full_match(&results[0]));
    }

    #[test]
    fn test_oracle_multi_table() {
        let words = test_words_path();
        let md5_idx = build_and_sort(&Md5, &words);
        let sha1_idx = build_and_sort(&Sha1, &words);

        let mut oracle = PreimageOracle::new();
        oracle
            .register("md5", MD5, md5_idx.path(), &words)
            .expect("register md5");
        oracle
            .register("sha1", SHA1, sha1_idx.path(), &words)
            .expect("register sha1");

        // MD5("apple")
        let results = oracle.crack(&["1f3870be274f6c49b3e31a0c6728957f"], false);
        assert_eq!(results.len(), 1);
        let HashResult::Lookup { matches, .. } = &results[0] else {
            panic!("expected Lookup variant");
        };
        let full: Vec<_> = matches
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
            .register("md5-first", MD5, idx1.path(), &words)
            .expect("register");
        oracle
            .register("md5-second", MD5, idx2.path(), &words)
            .expect("register");

        // With early_exit, should only find in first table
        let results = oracle.crack(&["1f3870be274f6c49b3e31a0c6728957f"], true);
        assert_eq!(results.len(), 1);
        let HashResult::Lookup { matches, .. } = &results[0] else {
            panic!("expected Lookup variant");
        };
        let full: Vec<_> = matches
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
            .register("md5", MD5, idx.path(), &words)
            .expect("register");

        let results = oracle.crack(&["ffffffffffffffffffffffffffffffff"], false);
        assert_eq!(results.len(), 1);
        let HashResult::Lookup { matches, .. } = &results[0] else {
            panic!("expected Lookup variant");
        };
        assert!(matches.is_empty());
    }

    #[test]
    fn test_oracle_batch() {
        let words = test_words_path();
        let idx = build_and_sort(&Md5, &words);

        let mut oracle = PreimageOracle::new();
        oracle
            .register("md5", MD5, idx.path(), &words)
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
        let HashResult::Lookup { matches, .. } = &results[1] else {
            panic!("expected Lookup variant for bogus hash");
        };
        assert!(matches.is_empty(), "bogus hash should not match");
    }

    #[test]
    fn test_oracle_invalid_format() {
        let words = test_words_path();
        let idx = build_and_sort(&Md5, &words);

        let mut oracle = PreimageOracle::new();
        oracle
            .register("md5", MD5, idx.path(), &words)
            .expect("register");

        let results = oracle.crack(
            &[
                "xyz",                                // non-hex
                "abc",                                // too short + odd
                "1f3870be274f6c49b3e31a0c6728957f",   // valid MD5("apple")
            ],
            false,
        );
        assert_eq!(results.len(), 3);

        assert!(
            matches!(&results[0], HashResult::InvalidFormat { input } if input == "xyz"),
            "non-hex should be InvalidFormat"
        );
        assert!(
            matches!(&results[1], HashResult::InvalidFormat { input } if input == "abc"),
            "too-short should be InvalidFormat"
        );
        assert!(has_full_match(&results[2]), "valid hash should be cracked");
    }

    #[test]
    fn test_oracle_invalid_mixed_with_valid() {
        let words = test_words_path();
        let idx = build_and_sort(&Md5, &words);

        let mut oracle = PreimageOracle::new();
        oracle
            .register("md5", MD5, idx.path(), &words)
            .expect("register");

        let results = oracle.crack(
            &[
                "1f3870be274f6c49b3e31a0c6728957f",   // valid: apple
                "not_hex_at_all!!",                    // invalid
                "ffffffffffffffffffffffffffffffff",   // valid: not found
                "abcde",                              // invalid: odd + short
            ],
            false,
        );
        assert_eq!(results.len(), 4);

        // First: valid, found
        assert!(has_full_match(&results[0]), "apple should be found");

        // Second: invalid
        assert!(
            matches!(&results[1], HashResult::InvalidFormat { input } if input == "not_hex_at_all!!"),
        );

        // Third: valid, not found
        let HashResult::Lookup { matches, .. } = &results[2] else {
            panic!("expected Lookup variant for not-found hash");
        };
        assert!(matches.is_empty());

        // Fourth: invalid
        assert!(
            matches!(&results[3], HashResult::InvalidFormat { input } if input == "abcde"),
        );
    }
}
