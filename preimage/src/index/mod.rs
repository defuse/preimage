use std::path::{Path, PathBuf};

pub(crate) mod builder;
pub(crate) mod checker;
pub mod entry;
pub mod lookup;
pub(crate) mod sorter;

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
