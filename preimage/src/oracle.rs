use std::path::Path;

use anyhow::Result;

use crate::index::lookup::{parse_hash_hex, LookupMatch, LookupTable};
use crate::HashAlgorithm;

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
        /// Matches retained for this hash, at most the requested per-hash limit.
        matches: Vec<OracleMatch<'a>>,
        /// How many matches were found across every table consulted, whether or not
        /// they were retained. Equal to `matches.len()` unless a limit truncated them.
        total_matches: usize,
    },
    /// The input was not a valid hash format (non-hex, odd-length, or too short).
    InvalidFormat { input: String },
}

/// Multi-table hash lookup oracle.
///
/// Register multiple `LookupTable`s and crack hashes against all of them.
#[derive(Default)]
pub struct PreimageOracle {
    tables: Vec<Table>,
}

struct Table {
    label: String,
    lookup: LookupTable,
}

impl PreimageOracle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a lookup table.
    ///
    /// # Trust
    ///
    /// The index and dictionary must be trusted and must not change while registered --
    /// see [`LookupTable::open`] for what a hostile or corrupt pair can do. In short: it
    /// can make this crate return wrong answers or kill the process, but it cannot read
    /// out of bounds.
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
    /// # Errors
    ///
    /// All or nothing, deliberately. A read failure against any one table abandons the
    /// whole batch rather than returning the hashes that did succeed, because a partial
    /// result is indistinguishable from a complete one at the call site: the caller would
    /// get plausible-looking rows with the failures silently missing from among them.
    /// A caller that wants per-hash resilience should call with one hash at a time.
    ///
    /// Iterates tables in registration order. For each table, tries ALL
    /// queried hashes before moving to the next table — this keeps the
    /// index mmap cache hot.
    ///
    /// If `early_exit` is true, a hash that already has a `Full` match
    /// is skipped for remaining tables.
    ///
    /// Returns results in the same order as the input hashes.
    ///
    /// No limit is applied: every match in every collision block is retained. A
    /// collision block is as large as the wordlist makes it, so a caller that renders
    /// or buffers these should use `crack_with_limit` instead.
    ///
    /// # Errors
    /// Returns an error if any table lookup fails (I/O error, corrupted index, etc.).
    pub fn crack<'a>(&'a self, hashes: &[&str], early_exit: bool) -> Result<Vec<HashResult<'a>>> {
        self.crack_with_limit(hashes, early_exit, usize::MAX)
    }

    /// Crack multiple hashes, retaining at most `limit_per_hash` matches for each.
    ///
    /// The limit is per queried hash and spans every table, so a batch of `n` hashes
    /// yields at most `n * limit_per_hash` matches however large the underlying
    /// collision blocks are. `usize::MAX` means unlimited, which is what `crack` passes.
    ///
    /// Every block is still walked in full, so `HashResult::total_matches` is the true
    /// count and a caller can say how much it is not showing. What the limit bounds is
    /// retention: the matches held in memory and whatever is built from them.
    ///
    /// Full matches survive the limit ahead of partial ones, so capping cannot turn a
    /// correct answer into a "not found" -- see `LookupTable::lookup_limited`.
    ///
    /// # Errors
    /// Returns an error if any table lookup fails (I/O error, corrupted index, etc.).
    pub fn crack_with_limit<'a>(
        &'a self,
        hashes: &[&str],
        early_exit: bool,
        limit_per_hash: usize,
    ) -> Result<Vec<HashResult<'a>>> {
        // Validate all hashes upfront. Invalid ones get InvalidFormat immediately.
        let mut results: Vec<HashResult<'a>> = hashes
            .iter()
            .map(|h| {
                if parse_hash_hex(h).is_ok() {
                    HashResult::Lookup {
                        queried_hash: h.to_string(),
                        matches: Vec::new(),
                        total_matches: 0,
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
                let HashResult::Lookup {
                    matches,
                    total_matches,
                    ..
                } = &mut results[i]
                else {
                    continue;
                };

                // Skip if early_exit and we already have a full match
                if early_exit && has_full_match_in(matches) {
                    continue;
                }

                // Spend the per-hash budget across tables: whatever earlier tables
                // already contributed is not available to this one.
                let remaining = limit_per_hash.saturating_sub(matches.len());
                let outcome = table.lookup.lookup_limited(hash_hex, remaining)?;

                // Counted even when `remaining` was zero, so the total stays truthful
                // once the budget is spent -- that number is the whole point of having
                // walked the block.
                *total_matches += outcome.total_matches;

                for lm in outcome.matches {
                    matches.push(OracleMatch {
                        table_label: &table.label,
                        lookup_match: lm,
                    });
                }
            }
        }

        Ok(results)
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
    use crate::index::sorter::IndexSorter;
    use crate::{Lm, Md5, Sha1, LM, MD5, SHA1};
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
        let results = oracle.crack(&["1f3870be274f6c49b3e31a0c6728957f"], false).expect("crack");
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
        let results = oracle.crack(&["1f3870be274f6c49b3e31a0c6728957f"], false).expect("crack");
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
        let results = oracle.crack(&["1f3870be274f6c49b3e31a0c6728957f"], true).expect("crack");
        assert_eq!(results.len(), 1);
        let HashResult::Lookup { matches, .. } = &results[0] else {
            panic!("expected Lookup variant");
        };
        let full: Vec<_> = matches
            .iter()
            .filter(|m| matches!(&m.lookup_match, LookupMatch::Full { .. }))
            .collect();
        assert_eq!(
            full.len(),
            1,
            "early_exit should stop after first full match"
        );
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

        let results = oracle.crack(&["ffffffffffffffffffffffffffffffff"], false).expect("crack");
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

        let results = oracle
            .crack(
                &[
                    "1f3870be274f6c49b3e31a0c6728957f", // apple
                    "ffffffffffffffffffffffffffffffff", // not found
                    "5d41402abc4b2a76b9719d911017c592", // hello (not in words.txt)
                ],
                false,
            )
            .expect("crack");
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

        let results = oracle
            .crack(
                &[
                    "xyz",                              // non-hex
                    "abc",                              // too short + odd
                    "1f3870be274f6c49b3e31a0c6728957f", // valid MD5("apple")
                ],
                false,
            )
            .expect("crack");
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

        let results = oracle
            .crack(
                &[
                    "1f3870be274f6c49b3e31a0c6728957f", // valid: apple
                    "not_hex_at_all!!",                 // invalid
                    "ffffffffffffffffffffffffffffffff", // valid: not found
                    "abcde",                            // invalid: odd + short
                ],
                false,
            )
            .expect("crack");
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
        assert!(matches!(&results[3], HashResult::InvalidFormat { input } if input == "abcde"),);
    }

    /// A wordlist whose entries all share an LM index prefix.
    ///
    /// LM's first eight output bytes are DES of a key expanded from the uppercased
    /// first seven characters, so every word starting "PASSWOR" lands in one collision
    /// block while hashing to a different full digest. That gives a block containing
    /// exactly one full match and many partial ones, which is the shape a limit has to
    /// handle correctly and which cannot be built out of a normal hash without finding
    /// a 64-bit collision.
    fn lm_collision_wordlist(count: usize, full_match_at: usize) -> (NamedTempFile, String) {
        use std::io::Write;
        let mut file = NamedTempFile::new().expect("temp file");
        let mut target = String::new();
        for i in 0..count {
            let word = format!("PASSWORD{i:03}");
            if i == full_match_at {
                target = word.clone();
            }
            writeln!(file, "{word}").expect("write");
        }
        file.flush().expect("flush");
        (file, target)
    }

    fn lm_oracle(words: &Path) -> (PreimageOracle, NamedTempFile) {
        let idx = build_and_sort(&Lm, words);
        let mut oracle = PreimageOracle::new();
        oracle.register("lm", LM, idx.path(), words).expect("register");
        (oracle, idx)
    }

    fn hex_of(algorithm: &dyn HashAlgorithm, word: &str) -> String {
        hex::encode(algorithm.hash(word.as_bytes()).expect("hash"))
    }

    /// The limit is per queried hash, and the count reported is the true one.
    #[test]
    fn limit_caps_matches_and_reports_the_real_total() {
        let (words, target) = lm_collision_wordlist(40, 0);
        let (oracle, _idx) = lm_oracle(words.path());
        let hash = hex_of(&Lm, &target);

        let unlimited = oracle.crack(&[hash.as_str()], false).expect("crack");
        let HashResult::Lookup { matches, total_matches, .. } = &unlimited[0] else {
            panic!("expected Lookup");
        };
        assert_eq!(matches.len(), 40, "unlimited must retain the whole block");
        assert_eq!(*total_matches, 40);

        let limited = oracle
            .crack_with_limit(&[hash.as_str()], false, 5)
            .expect("crack");
        let HashResult::Lookup { matches, total_matches, .. } = &limited[0] else {
            panic!("expected Lookup");
        };
        assert_eq!(matches.len(), 5, "the limit must cap what is retained");
        assert_eq!(
            *total_matches, 40,
            "the total must stay truthful so a caller can say what it is not showing"
        );
    }

    /// The property that makes the cap safe rather than merely small: an exact match
    /// buried deep in the block must still be returned. A cap applied in index order
    /// would drop it and report "not found" for a hash that is in the dictionary.
    #[test]
    fn a_full_match_survives_a_limit_that_excludes_its_position() {
        // The answer sits at index 30 of a 40-entry block, well past a limit of 3.
        let (words, target) = lm_collision_wordlist(40, 30);
        let (oracle, _idx) = lm_oracle(words.path());
        let hash = hex_of(&Lm, &target);

        let results = oracle
            .crack_with_limit(&[hash.as_str()], false, 3)
            .expect("crack");
        let HashResult::Lookup { matches, total_matches, .. } = &results[0] else {
            panic!("expected Lookup");
        };

        assert_eq!(matches.len(), 3);
        assert_eq!(*total_matches, 40);
        assert!(
            has_full_match(&results[0]),
            "the exact match must survive the limit -- losing it turns a correct answer \
             into a confident 'not found'"
        );
        assert!(
            matches[0].lookup_match.is_full(),
            "full matches come first, so the answer is not buried among near misses"
        );
        assert_eq!(
            matches[0].lookup_match.plaintext(),
            target.as_bytes(),
            "and it must be the right plaintext"
        );
    }

    /// The budget is per hash and spans tables, so a batch is bounded by
    /// `hashes * limit` however large the blocks are.
    #[test]
    fn the_budget_is_per_hash_and_spans_tables() {
        let (words, target) = lm_collision_wordlist(40, 0);
        let idx_a = build_and_sort(&Lm, words.path());
        let idx_b = build_and_sort(&Lm, words.path());

        let mut oracle = PreimageOracle::new();
        oracle.register("lm-a", LM, idx_a.path(), words.path()).expect("register a");
        oracle.register("lm-b", LM, idx_b.path(), words.path()).expect("register b");

        let hash = hex_of(&Lm, &target);
        let results = oracle
            .crack_with_limit(&[hash.as_str(), hash.as_str()], false, 5)
            .expect("crack");

        assert_eq!(results.len(), 2);
        for result in &results {
            let HashResult::Lookup { matches, total_matches, .. } = result else {
                panic!("expected Lookup");
            };
            assert_eq!(
                matches.len(),
                5,
                "two identical tables must not each get their own budget"
            );
            assert_eq!(*total_matches, 80, "both tables' matches are counted");
        }
    }

    /// A limit of zero still walks and counts, so a caller can report the size of what
    /// it declined to retain.
    #[test]
    fn a_zero_limit_retains_nothing_but_still_counts() {
        let (words, target) = lm_collision_wordlist(12, 0);
        let (oracle, _idx) = lm_oracle(words.path());
        let hash = hex_of(&Lm, &target);

        let results = oracle
            .crack_with_limit(&[hash.as_str()], false, 0)
            .expect("crack");
        let HashResult::Lookup { matches, total_matches, .. } = &results[0] else {
            panic!("expected Lookup");
        };
        assert!(matches.is_empty());
        assert_eq!(*total_matches, 12);
    }

    /// `crack` keeps its old meaning: no limit at all.
    #[test]
    fn crack_is_unlimited_by_default() {
        let (words, target) = lm_collision_wordlist(25, 0);
        let (oracle, _idx) = lm_oracle(words.path());
        let hash = hex_of(&Lm, &target);

        let results = oracle.crack(&[hash.as_str()], false).expect("crack");
        let HashResult::Lookup { matches, total_matches, .. } = &results[0] else {
            panic!("expected Lookup");
        };
        assert_eq!(matches.len(), 25);
        assert_eq!(*total_matches, 25);
    }

}
