use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};

use preimage::{
    get_algorithm, HashAlgorithm, HashResult, IndexFile, PreimageOracle, ALGORITHM_NAMES,
};

#[path = "shared/memory_size.rs"]
mod memory_size;
use memory_size::parse_memory_size;

#[derive(Parser)]
#[command(
    name = "preimage",
    about = "Preimage creates hash indexes for wordlists, enabling speedy, space-efficient hash cracking.",
    flatten_help = true,
    after_help = "\
WORKFLOW:
  1. Create an index from a wordlist:
       preimage create -a md5 -w wordlist.txt -o md5.idx

  2. Sort the index (WARNING: do not interrupt, corrupts the file):
       preimage sort md5.idx
       preimage sort --ram md5.idx          # load entirely into RAM
       preimage sort --memory 4G md5.idx     # use 4 GiB buffer

  3. Verify the index is sorted:
       preimage check md5.idx

  4. Look up hashes:
       preimage lookup -a md5 -i md5.idx -d wordlist.txt <hash>...
       preimage lookup --config tables.toml <hash>...

  5. List supported algorithms:
       preimage list

Wordlists are arbitrary bytes separated by \\n characters.

EXAMPLE CONFIG (tables.toml):
  [[table]]
  label = \"md5-small\"
  algorithm = \"md5\"
  index = \"/data/md5-small.idx\"
  dictionary = \"/data/small.txt\"

  [[table]]
  label = \"md5-large\"
  algorithm = \"md5\"
  index = \"/data/md5-large.idx\"
  dictionary = \"/data/large.txt\"

  [[table]]
  label = \"sha1-small\"
  algorithm = \"sha1\"
  index = \"/data/sha1-small.idx\"
  dictionary = \"/data/small.txt\""
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create an unsorted index from a wordlist, or a folder of wordlists
    Create(CreateArgs),
    /// Sort an index file in-place (DO NOT INTERRUPT)
    #[command(after_help = "\
WARNING: Sorting modifies the file in-place. Do NOT interrupt the process \
(e.g. Ctrl+C) or the index file will be corrupted and must be regenerated.

EXAMPLES:
  Sort with default 2 GiB buffer:
    preimage sort md5.idx

  Sort with 4 GiB buffer:
    preimage sort --memory 4G md5.idx

  Sort entirely in RAM:
    preimage sort --ram md5.idx")]
    Sort {
        /// Sort buffer size (e.g. 256M, 4G, 1024K)
        #[arg(short, long, default_value = "2G", value_parser = parse_memory_size)]
        memory: usize,
        /// Load the entire index into RAM. Errors if the allocator refuses the
        /// request; note that under Linux overcommit the allocation usually
        /// succeeds and the process is OOM-killed instead, so this is not a
        /// guarantee that the index fits in available memory.
        #[arg(long)]
        ram: bool,
        /// Path to the index file
        index: PathBuf,
    },
    /// Verify that an index file is sorted
    #[command(after_help = "\
EXAMPLE:
  preimage check md5.idx")]
    Check {
        /// Path to the index file
        index: PathBuf,
    },
    /// Look up hashes against index(es)
    Lookup(LookupArgs),
    /// List supported hash algorithms
    List,
}

/// How to ingest a `--dir` of wordlists.
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum DirMode {
    /// Concatenate every file into one dictionary and build a single index over it.
    /// One binary search per lookup; rebuild the whole thing to add a file.
    Combined,
    /// Build one index per file and write a config listing them all. Lookups search
    /// every table; add a file without rebuilding the others.
    Separate,
}

#[derive(clap::Args)]
#[command(after_help = "\
EXAMPLES:
  One wordlist:
    preimage create -a md5 -w wordlist.txt -o md5.idx

  A folder, combined into one index (one dictionary, fastest lookups):
    preimage create -a md5 --dir words/ --mode combined -o all.idx --dict all.txt

  A folder, one index per file (add files later without rebuilding):
    preimage create -a md5 --dir words/ --mode separate --out-dir idx/ --config tables.toml")]
struct CreateArgs {
    /// Hash algorithm name (run 'preimage list' to list)
    #[arg(short, long)]
    algorithm: String,
    /// Path to a single wordlist file (mutually exclusive with --dir)
    #[arg(short, long)]
    wordlist: Option<PathBuf>,
    /// Path to a folder of wordlist files to ingest together
    #[arg(long)]
    dir: Option<PathBuf>,
    /// With --dir: one combined index, or one index per file
    #[arg(long, value_enum, default_value = "combined")]
    mode: DirMode,
    /// Output index path (single wordlist, or --dir --mode combined)
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Where to write the concatenated dictionary (--dir --mode combined)
    #[arg(long)]
    dict: Option<PathBuf>,
    /// Output directory for the per-file indexes (--dir --mode separate)
    #[arg(long)]
    out_dir: Option<PathBuf>,
    /// Config file to write, listing the per-file tables (--dir --mode separate)
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(clap::Args)]
#[command(after_help = "\
EXAMPLES:
  Single-table lookup:
    preimage lookup -a md5 -i index.idx -d words.txt 5d41402abc4b2a76b9719d911017c592

  Multi-table lookup:
    preimage lookup --config tables.toml --early-exit 5d41402abc4b2a76b9719d911017c592")]
struct LookupArgs {
    /// Hash algorithm (for single-table lookup)
    #[arg(short, long)]
    algorithm: Option<String>,
    /// Index file path (for single-table lookup)
    #[arg(short, long)]
    index: Option<PathBuf>,
    /// Dictionary/wordlist file path (for single-table lookup)
    #[arg(short, long)]
    dictionary: Option<PathBuf>,
    /// Config file path (for multi-table lookup)
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Stop after first full match per hash
    #[arg(long)]
    early_exit: bool,
    /// Hex-encoded hash(es) to look up
    hashes: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Create(args) => cmd_create(args),
        Commands::Sort { memory, ram, index } => cmd_sort(memory, ram, &index),
        Commands::Check { index } => cmd_check(&index),
        Commands::Lookup(args) => cmd_lookup(args),
        Commands::List => cmd_algorithms(),
    }
}

fn algorithm_from_name(name: &str) -> &'static dyn HashAlgorithm {
    get_algorithm(name).unwrap_or_else(|| {
        eprintln!("Unknown algorithm: {name}");
        eprintln!("Run 'preimage list' to see supported algorithms.");
        process::exit(1);
    })
}

fn cmd_create(args: CreateArgs) -> Result<()> {
    let algorithm = algorithm_from_name(&args.algorithm);

    match (args.wordlist.as_ref(), args.dir.as_ref()) {
        (Some(_), Some(_)) => {
            bail!("pass either --wordlist <file> or --dir <folder>, not both")
        }
        (None, None) => {
            bail!("pass --wordlist <file> to index one file, or --dir <folder> to index a folder")
        }
        (Some(wordlist), None) => {
            let output = args
                .output
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("--output <index> is required with --wordlist"))?;
            create_one(algorithm, wordlist, output)
        }
        (None, Some(dir)) => {
            let files = list_wordlist_files(dir)?;
            if files.is_empty() {
                bail!("no files found in {}", dir.display());
            }
            println!(
                "Found {} wordlist file(s) in {}.",
                files.len(),
                dir.display()
            );
            match args.mode {
                DirMode::Combined => {
                    let output = args.output.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("--output <index> is required for --mode combined")
                    })?;
                    let dict = args.dict.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("--dict <dictionary> is required for --mode combined")
                    })?;
                    create_combined(&args.algorithm, algorithm, &files, dict, output)
                }
                DirMode::Separate => {
                    let out_dir = args.out_dir.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("--out-dir <dir> is required for --mode separate")
                    })?;
                    let config = args.config.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("--config <tables.toml> is required for --mode separate")
                    })?;
                    create_separate(&args.algorithm, algorithm, &files, out_dir, config)
                }
            }
        }
    }
}

/// A bytes-based progress bar matching the style `create` has always used.
fn create_progress_bar() -> ProgressBar {
    let pb = ProgressBar::new(0);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .expect("valid template")
            .progress_chars("#>-"),
    );
    pb
}

/// Index a single wordlist file — the original `create` behaviour.
fn create_one(algorithm: &dyn HashAlgorithm, wordlist: &Path, output: &Path) -> Result<()> {
    let pb = create_progress_bar();
    let index = IndexFile::build(algorithm, wordlist, output, Some(&pb))?;
    pb.finish_and_clear();
    let count = index.entry_count()?;
    println!("Index creation complete. {count} entries written.");
    Ok(())
}

/// Concatenate a folder into one dictionary and build a single index over it.
fn create_combined(
    algorithm_name: &str,
    algorithm: &dyn HashAlgorithm,
    files: &[PathBuf],
    dict_path: &Path,
    index_path: &Path,
) -> Result<()> {
    for f in files {
        if same_existing_path(f, dict_path) || same_existing_path(f, index_path) {
            bail!(
                "the combined dictionary or index would overwrite an input file ({}); \
                 write them outside the --dir folder",
                f.display()
            );
        }
    }

    println!("Concatenating into {} ...", dict_path.display());
    concatenate_files(files, dict_path)?;

    let pb = create_progress_bar();
    let index = IndexFile::build(algorithm, dict_path, index_path, Some(&pb))?;
    pb.finish_and_clear();
    let count = index.entry_count()?;

    println!(
        "Index creation complete. {count} entries written to {}.",
        index_path.display()
    );
    println!("Next:");
    println!("  preimage sort {}", index_path.display());
    println!(
        "  preimage lookup -a {} -i {} -d {} <hash>",
        algorithm_name,
        index_path.display(),
        dict_path.display()
    );
    Ok(())
}

/// Build one index per file and write a config listing them for `lookup --config`.
fn create_separate(
    algorithm_name: &str,
    algorithm: &dyn HashAlgorithm,
    files: &[PathBuf],
    out_dir: &Path,
    config_path: &Path,
) -> Result<()> {
    std::fs::create_dir_all(out_dir)?;

    // Plan every output before opening any of them. This prevents an output for one
    // wordlist (for example `foo.idx`) from truncating another input file with that
    // name, and prevents the config path from colliding with either an input or index.
    let mut tables = Vec::with_capacity(files.len());
    for f in files {
        let name = f
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("wordlist path has no file name: {}", f.display()))?
            .to_string_lossy()
            .into_owned();
        tables.push(TableConfig {
            label: name.clone(),
            algorithm: algorithm_name.to_string(),
            index: out_dir.join(format!("{name}.idx")),
            dictionary: f.clone(),
        });
    }
    validate_separate_paths(files, &tables, config_path)?;

    for table in &tables {
        println!(
            "Indexing {} -> {}",
            table.dictionary.display(),
            table.index.display()
        );
        let pb = create_progress_bar();
        IndexFile::build(algorithm, &table.dictionary, &table.index, Some(&pb))?;
        pb.finish_and_clear();
    }

    let config = Config { table: tables };
    let rendered = toml::to_string_pretty(&config)?;
    std::fs::write(config_path, rendered)?;

    println!(
        "Wrote {} table(s) to {}.",
        config.table.len(),
        config_path.display()
    );
    println!("Next — sort each index:");
    for table in &config.table {
        println!("  preimage sort {}", table.index.display());
    }
    println!(
        "Then: preimage lookup --config {} <hash>",
        config_path.display()
    );
    Ok(())
}

/// Refuse a separate-mode plan if any generated file aliases an input or another
/// generated file. Validation happens before the first index is opened for writing.
fn validate_separate_paths(
    files: &[PathBuf],
    tables: &[TableConfig],
    config_path: &Path,
) -> Result<()> {
    for table in tables {
        for input in files {
            if same_target_path(input, &table.index)? {
                bail!(
                    "generated index {} would overwrite input wordlist {}",
                    table.index.display(),
                    input.display()
                );
            }
        }

        if same_target_path(&table.index, config_path)? {
            bail!(
                "config path {} would overwrite generated index {}",
                config_path.display(),
                table.index.display()
            );
        }
    }

    for input in files {
        if same_target_path(input, config_path)? {
            bail!(
                "config path {} would overwrite input wordlist {}",
                config_path.display(),
                input.display()
            );
        }
    }

    for (i, left) in tables.iter().enumerate() {
        for right in &tables[i + 1..] {
            if same_target_path(&left.index, &right.index)? {
                bail!(
                    "generated indexes {} and {} resolve to the same output file",
                    left.index.display(),
                    right.index.display()
                );
            }
        }
    }

    Ok(())
}

/// The regular files directly inside `dir`, sorted by path for a deterministic,
/// reproducible ingest order. Subdirectories are skipped.
fn list_wordlist_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

/// Concatenate `files` into `out_path`, guaranteeing a `\n` between files so the last
/// word of one and the first word of the next do not merge into a single line.
fn concatenate_files(files: &[PathBuf], out_path: &Path) -> Result<()> {
    let mut out = BufWriter::new(File::create(out_path)?);
    let mut buf = vec![0u8; 1 << 20];
    for f in files {
        let mut reader = File::open(f)?;
        let mut last_byte = None;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            last_byte = Some(buf[n - 1]);
        }
        // Only add a separator when the file was non-empty and did not end in one,
        // so we neither merge words nor inject spurious empty lines.
        if matches!(last_byte, Some(b) if b != b'\n') {
            out.write_all(b"\n")?;
        }
    }
    out.flush()?;
    Ok(())
}

/// Whether `a` and `b` resolve to the same existing file. Paths that do not exist yet
/// (the usual case for an output) cannot alias one that does, so they answer `false`.
fn same_existing_path(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(a_meta), Ok(b_meta)) = (std::fs::metadata(a), std::fs::metadata(b)) {
            if a_meta.dev() == b_meta.dev() && a_meta.ino() == b_meta.ino() {
                return true;
            }
        }
    }

    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Compare two paths as eventual output targets, even if one does not exist yet.
/// Existing files use their canonical identity (and inode on Unix); non-existent
/// paths canonicalize their parent directory and append the final path component.
fn same_target_path(a: &Path, b: &Path) -> Result<bool> {
    if same_existing_path(a, b) {
        return Ok(true);
    }

    fn target_path(path: &Path) -> Result<PathBuf> {
        if path.exists() {
            return Ok(path.canonicalize()?);
        }

        let name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("output path has no file name: {}", path.display()))?;
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        Ok(parent.canonicalize()?.join(name))
    }

    Ok(target_path(a)? == target_path(b)?)
}

fn cmd_sort(memory_bytes: usize, ram_only: bool, index_path: &PathBuf) -> Result<()> {
    eprintln!("WARNING: Do not interrupt this process. The index file will be corrupted if sorting is interrupted.");
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .expect("valid template"),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let index = IndexFile::open(index_path);
    if ram_only {
        index.sort_ram_only(Some(&pb))?;
    } else {
        index.sort(memory_bytes, Some(&pb))?;
    }
    pb.finish_and_clear();
    println!("Index sort complete.");
    Ok(())
}

fn cmd_check(index_path: &PathBuf) -> Result<()> {
    let pb = ProgressBar::new(0);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} entries",
            )
            .expect("valid template")
            .progress_chars("#>-"),
    );

    let index = IndexFile::open(index_path);
    let sorted = index.check_sorted(Some(&pb))?;
    pb.finish_and_clear();

    if sorted {
        println!("Index is sorted.");
    } else {
        println!("Index is NOT sorted.");
        process::exit(1);
    }
    Ok(())
}

fn cmd_lookup(args: LookupArgs) -> Result<()> {
    if args.hashes.is_empty() {
        bail!("No hashes provided. Pass one or more hex-encoded hashes, e.g.:\n  preimage lookup -a md5 -i index.idx -d words.txt 5d41402abc4b2a76b9719d911017c592");
    }

    if let Some(config_path) = &args.config {
        return lookup_with_config(config_path, &args.hashes, args.early_exit);
    }

    if let (Some(alg_name), Some(index_path), Some(dict_path)) =
        (&args.algorithm, &args.index, &args.dictionary)
    {
        lookup_single(alg_name, index_path, dict_path, &args.hashes)
    } else {
        bail!("Provide either --config for multi-table lookup, or --algorithm, --index, and --dictionary for single-table lookup.");
    }
}

fn lookup_single(
    algorithm_name: &str,
    index_path: &Path,
    dict_path: &Path,
    hashes: &[String],
) -> Result<()> {
    let algorithm = algorithm_from_name(algorithm_name);
    let table = IndexFile::open(index_path).into_lookup_table(algorithm, dict_path)?;

    for hash_hex in hashes {
        let matches = table.lookup(hash_hex)?;
        if matches.is_empty() {
            println!("{hash_hex}: NOT FOUND");
        } else {
            for m in &matches {
                let plaintext = m.plaintext_lossy();
                if m.is_full() {
                    println!("{hash_hex}: {plaintext} [{}]", m.algorithm().name());
                } else {
                    println!(
                        "{hash_hex}: {plaintext} [{}] (partial, full hash: {})",
                        m.algorithm().name(),
                        hex::encode(m.recomputed_hash())
                    );
                }
            }
        }
    }
    Ok(())
}

#[derive(serde::Deserialize, serde::Serialize)]
struct Config {
    table: Vec<TableConfig>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct TableConfig {
    label: String,
    algorithm: String,
    index: PathBuf,
    dictionary: PathBuf,
}

fn lookup_with_config(config_path: &PathBuf, hashes: &[String], early_exit: bool) -> Result<()> {
    let config_str = std::fs::read_to_string(config_path)?;
    let config: Config = toml::from_str(&config_str)?;

    let mut oracle = PreimageOracle::new();
    for tc in &config.table {
        let algorithm = algorithm_from_name(&tc.algorithm);
        oracle.register(&tc.label, algorithm, &tc.index, &tc.dictionary)?;
    }

    let hash_refs: Vec<&str> = hashes.iter().map(|s| s.as_str()).collect();
    let results = oracle.crack(&hash_refs, early_exit)?;

    for result in &results {
        match result {
            HashResult::InvalidFormat { input } => {
                println!("{}: INVALID FORMAT", input);
            }
            HashResult::Lookup {
                queried_hash,
                matches,
                ..
            } if matches.is_empty() => {
                println!("{}: NOT FOUND", queried_hash);
            }
            HashResult::Lookup {
                queried_hash,
                matches,
                ..
            } => {
                for m in matches {
                    let lm = &m.lookup_match;
                    let plaintext = lm.plaintext_lossy();
                    if lm.is_full() {
                        println!(
                            "{}: {} [{}] ({})",
                            queried_hash,
                            plaintext,
                            m.table_label,
                            lm.algorithm().name()
                        );
                    } else {
                        println!(
                            "{}: {} [{}] ({}, partial, full hash: {})",
                            queried_hash,
                            plaintext,
                            m.table_label,
                            lm.algorithm().name(),
                            hex::encode(lm.recomputed_hash())
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn cmd_algorithms() -> Result<()> {
    for name in ALGORITHM_NAMES {
        println!("{name}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_wordlist_files_is_sorted_and_skips_subdirs() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join("b.txt"), b"x").expect("write");
        std::fs::write(dir.path().join("a.txt"), b"y").expect("write");
        std::fs::write(dir.path().join("c.txt"), b"z").expect("write");
        std::fs::create_dir(dir.path().join("nested")).expect("subdir");

        let files = list_wordlist_files(dir.path()).expect("list");
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["a.txt", "b.txt", "c.txt"],
            "files must be returned sorted, with subdirectories skipped"
        );
    }

    #[test]
    fn concatenate_inserts_a_separator_only_when_one_is_missing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ends_nl = dir.path().join("a");
        std::fs::write(&ends_nl, b"one\ntwo\n").expect("write");
        let no_nl = dir.path().join("b");
        std::fs::write(&no_nl, b"three\nfour").expect("write");
        let empty = dir.path().join("c");
        std::fs::write(&empty, b"").expect("write");
        let also_nl = dir.path().join("d");
        std::fs::write(&also_nl, b"five\n").expect("write");

        let out = dir.path().join("combined.txt");
        concatenate_files(&[ends_nl, no_nl, empty, also_nl], &out).expect("concat");

        // A missing terminator is added (between "four" and "five"); existing ones are
        // not doubled, and the empty file contributes nothing.
        assert_eq!(
            std::fs::read(&out).expect("read"),
            b"one\ntwo\nthree\nfour\nfive\n".to_vec()
        );
    }

    #[test]
    fn separate_mode_refuses_an_index_that_would_overwrite_another_input() {
        let dir = tempfile::tempdir().expect("temp dir");
        let foo = dir.path().join("foo");
        let foo_idx = dir.path().join("foo.idx");
        std::fs::write(&foo, b"alpha\n").expect("write foo");
        std::fs::write(&foo_idx, b"DO NOT OVERWRITE\n").expect("write foo.idx");
        let original = std::fs::read(&foo_idx).expect("read original");
        let config = dir.path().join("tables.toml");

        let error = create_separate(
            "md5",
            algorithm_from_name("md5"),
            &[foo, foo_idx.clone()],
            dir.path(),
            &config,
        )
        .expect_err("an index output must not overwrite another input file");

        assert!(
            error.to_string().contains("would overwrite input wordlist"),
            "unexpected error: {error}"
        );
        assert_eq!(
            std::fs::read(&foo_idx).expect("read after refusal"),
            original,
            "validation must happen before any input is truncated"
        );
        assert!(!config.exists(), "config must not be written after refusal");
    }

    #[test]
    fn separate_mode_refuses_a_config_that_collides_with_an_index() {
        let dir = tempfile::tempdir().expect("temp dir");
        let source_dir = dir.path().join("words");
        let out_dir = dir.path().join("idx");
        std::fs::create_dir(&source_dir).expect("source dir");
        let words = source_dir.join("words.txt");
        std::fs::write(&words, b"alpha\n").expect("write words");
        let config = out_dir.join("words.txt.idx");

        let error = create_separate(
            "md5",
            algorithm_from_name("md5"),
            &[words],
            &out_dir,
            &config,
        )
        .expect_err("config must not share a generated index path");

        assert!(
            error
                .to_string()
                .contains("would overwrite generated index"),
            "unexpected error: {error}"
        );
        assert!(
            !config.exists(),
            "validation must happen before the colliding output is created"
        );
    }

    #[test]
    fn config_round_trips_through_toml() {
        let config = Config {
            table: vec![TableConfig {
                label: "a.txt".into(),
                algorithm: "md5".into(),
                index: PathBuf::from("idx/a.txt.idx"),
                dictionary: PathBuf::from("folder/a.txt"),
            }],
        };
        let rendered = toml::to_string_pretty(&config).expect("serialize");
        let parsed: Config = toml::from_str(&rendered).expect("deserialize");

        assert_eq!(parsed.table.len(), 1);
        assert_eq!(parsed.table[0].label, "a.txt");
        assert_eq!(parsed.table[0].algorithm, "md5");
        assert_eq!(parsed.table[0].index, PathBuf::from("idx/a.txt.idx"));
        assert_eq!(parsed.table[0].dictionary, PathBuf::from("folder/a.txt"));
    }
}
