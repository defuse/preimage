use std::path::PathBuf;
use std::process;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};

use preimage::{get_algorithm, HashAlgorithm, HashResult, IndexFile, PreimageOracle, ALGORITHM_NAMES};

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
    /// Create an unsorted index from a wordlist
    #[command(after_help = "\
EXAMPLE:
  preimage create -a md5 -w wordlist.txt -o md5.idx")]
    Create {
        /// Hash algorithm name (run 'preimage list' to list)
        #[arg(short, long)]
        algorithm: String,
        /// Path to the wordlist file
        #[arg(short, long)]
        wordlist: PathBuf,
        /// Path to the output index file
        #[arg(short, long)]
        output: PathBuf,
    },
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
        /// Load entire file into RAM; error if it doesn't fit
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

#[derive(clap::Args)]
#[command(
    after_help = "\
EXAMPLES:
  Single-table lookup:
    preimage lookup -a md5 -i index.idx -d words.txt 5d41402abc4b2a76b9719d911017c592

  Multi-table lookup:
    preimage lookup --config tables.toml --early-exit 5d41402abc4b2a76b9719d911017c592"
)]
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

fn parse_memory_size(s: &str) -> std::result::Result<usize, String> {
    let s = s.trim();
    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('G') {
        (n, 1024 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix('M') {
        (n, 1024 * 1024)
    } else if let Some(n) = s.strip_suffix('K') {
        (n, 1024)
    } else {
        return Err("missing suffix: use K, M, or G (e.g. 256M, 4G)".to_string());
    };

    let num: f64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid number: {num_str:?}"))?;

    if num < 0.0 {
        return Err("memory size cannot be negative".to_string());
    }

    Ok((num * multiplier as f64) as usize)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Create {
            algorithm,
            wordlist,
            output,
        } => cmd_create(&algorithm, &wordlist, &output),
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

fn cmd_create(algorithm_name: &str, wordlist: &PathBuf, output: &PathBuf) -> Result<()> {
    let algorithm = algorithm_from_name(algorithm_name);

    let pb = ProgressBar::new(0);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .expect("valid template")
            .progress_chars("#>-"),
    );

    let index = IndexFile::build(algorithm, wordlist, output, Some(&pb))?;
    pb.finish_and_clear();
    let count = index.entry_count()?;
    println!("Index creation complete. {count} entries written.");
    Ok(())
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
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} entries")
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
    index_path: &PathBuf,
    dict_path: &PathBuf,
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

#[derive(serde::Deserialize)]
struct Config {
    table: Vec<TableConfig>,
}

#[derive(serde::Deserialize)]
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
    let results = oracle.crack(&hash_refs, early_exit);

    for result in &results {
        match result {
            HashResult::InvalidFormat { input } => {
                println!("{}: INVALID FORMAT", input);
            }
            HashResult::Lookup { queried_hash, matches } if matches.is_empty() => {
                println!("{}: NOT FOUND", queried_hash);
            }
            HashResult::Lookup { queried_hash, matches } => {
                for m in matches {
                    let lm = &m.lookup_match;
                    let plaintext = lm.plaintext_lossy();
                    if lm.is_full() {
                        println!(
                            "{}: {} [{}] ({})",
                            queried_hash, plaintext, m.table_label, lm.algorithm().name()
                        );
                    } else {
                        println!(
                            "{}: {} [{}] ({}, partial, full hash: {})",
                            queried_hash, plaintext, m.table_label,
                            lm.algorithm().name(), hex::encode(lm.recomputed_hash())
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
