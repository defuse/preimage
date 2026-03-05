use std::path::PathBuf;
use std::process;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};

use preimage::builder::IndexBuilder;
use preimage::checker::check_sorted;
use preimage::hashing::{self, HashAlgorithm};
use preimage::lookup::{LookupMatch, LookupTable};
#[cfg(feature = "config")]
use preimage::oracle::PreimageOracle;
use preimage::sorter::IndexSorter;

#[derive(Parser)]
#[command(
    name = "preimage",
    about = "Hash lookup table toolkit",
    after_help = "\
WORKFLOW:
  1. Create an index from a wordlist:
       preimage create md5 wordlist.txt md5.idx

  2. Sort the index (WARNING: do not interrupt, corrupts the file):
       preimage sort md5.idx
       preimage sort --ram md5.idx          # load entirely into RAM
       preimage sort --memory 4096 md5.idx  # use 4 GiB buffer

  3. Verify the index is sorted:
       preimage check md5.idx

  4. Look up hashes:
       preimage lookup -a md5 -i md5.idx -d wordlist.txt <hash>...
       preimage lookup --config tables.toml <hash>...

  5. List supported algorithms:
       preimage algorithms

Run 'preimage <command> --help' for detailed options."
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
  preimage create md5 wordlist.txt md5.idx")]
    Create {
        /// Hash algorithm name (run 'preimage algorithms' to list)
        algorithm: String,
        /// Path to the wordlist file
        wordlist: PathBuf,
        /// Path to the output index file
        output: PathBuf,
    },
    /// Sort an index file in-place
    #[command(after_help = "\
WARNING: Sorting modifies the file in-place. Do NOT interrupt the process \
(e.g. Ctrl+C) or the index file will be corrupted and must be regenerated.

EXAMPLES:
  Sort with default 256 MiB buffer:
    preimage sort md5.idx

  Sort with 4 GiB buffer:
    preimage sort --memory 4096 md5.idx

  Sort entirely in RAM:
    preimage sort --ram md5.idx")]
    Sort {
        /// Sort buffer size in MiB
        #[arg(short, long, default_value_t = 256)]
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
    Algorithms,
}

#[derive(clap::Args)]
#[command(
    after_help = "\
EXAMPLES:
  Single-table lookup:
    preimage lookup -a md5 -i index.idx -d words.txt 5d41402abc4b2a76b9719d911017c592

  Multi-table lookup (requires 'config' feature):
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
    #[cfg(feature = "config")]
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Stop after first full match per hash
    #[cfg(feature = "config")]
    #[arg(long)]
    early_exit: bool,
    /// Hex-encoded hash(es) to look up
    hashes: Vec<String>,
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
        Commands::Algorithms => cmd_algorithms(),
    }
}

fn algorithm_from_name(name: &str) -> Box<dyn HashAlgorithm> {
    hashing::get_algorithm(name).unwrap_or_else(|| {
        eprintln!("Unknown algorithm: {name}");
        eprintln!("Run `preimage algorithms` to see supported algorithms.");
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

    let count = IndexBuilder::build(&*algorithm, wordlist, output, Some(&pb))?;
    pb.finish_and_clear();
    println!("Index creation complete. {count} entries written.");
    Ok(())
}

fn cmd_sort(memory_mib: usize, ram_only: bool, index: &PathBuf) -> Result<()> {
    eprintln!("WARNING: Do not interrupt this process. The index file will be corrupted if sorting is interrupted.");
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .expect("valid template"),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let mut sorter = IndexSorter::new(memory_mib);
    if ram_only {
        sorter.sort_ram_only(index, Some(&pb))?;
    } else {
        sorter.sort(index, Some(&pb))?;
    }
    pb.finish_and_clear();
    println!("Index sort complete.");
    Ok(())
}

fn cmd_check(index: &PathBuf) -> Result<()> {
    let pb = ProgressBar::new(0);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} entries")
            .expect("valid template")
            .progress_chars("#>-"),
    );

    let sorted = check_sorted(index, Some(&pb))?;
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

    #[cfg(feature = "config")]
    if let Some(config_path) = &args.config {
        return lookup_with_config(config_path, &args.hashes, args.early_exit);
    }

    if let (Some(alg_name), Some(index_path), Some(dict_path)) =
        (&args.algorithm, &args.index, &args.dictionary)
    {
        lookup_single(alg_name, index_path, dict_path, &args.hashes)
    } else {
        #[cfg(feature = "config")]
        bail!("Provide either --config for multi-table lookup, or --algorithm, --index, and --dictionary for single-table lookup.");
        #[cfg(not(feature = "config"))]
        bail!("Provide --algorithm, --index, and --dictionary for lookup.");
    }
}

fn lookup_single(
    algorithm_name: &str,
    index_path: &PathBuf,
    dict_path: &PathBuf,
    hashes: &[String],
) -> Result<()> {
    let algorithm = algorithm_from_name(algorithm_name);
    let table = LookupTable::open_boxed(algorithm, index_path, dict_path)?;

    for hash_hex in hashes {
        let matches = table.lookup(hash_hex)?;
        if matches.is_empty() {
            println!("{hash_hex}: NOT FOUND");
        } else {
            for m in &matches {
                let plaintext = m.plaintext_lossy();
                match m {
                    LookupMatch::Full { algorithm, .. } => {
                        println!("{hash_hex}: {plaintext} [{}]", algorithm.name());
                    }
                    LookupMatch::Partial {
                        algorithm,
                        recomputed_hash,
                        ..
                    } => {
                        println!(
                            "{hash_hex}: {plaintext} [{}] (partial, full hash: {})",
                            algorithm.name(),
                            hex::encode(recomputed_hash)
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(feature = "config")]
#[derive(serde::Deserialize)]
struct Config {
    table: Vec<TableConfig>,
}

#[cfg(feature = "config")]
#[derive(serde::Deserialize)]
struct TableConfig {
    label: String,
    algorithm: String,
    index: PathBuf,
    dictionary: PathBuf,
}

#[cfg(feature = "config")]
fn lookup_with_config(config_path: &PathBuf, hashes: &[String], early_exit: bool) -> Result<()> {
    let config_str = std::fs::read_to_string(config_path)?;
    let config: Config = toml::from_str(&config_str)?;

    let mut oracle = PreimageOracle::new();
    for tc in &config.table {
        let algorithm = algorithm_from_name(&tc.algorithm);
        oracle.register_boxed(&tc.label, algorithm, &tc.index, &tc.dictionary)?;
    }

    let hash_refs: Vec<&str> = hashes.iter().map(|s| s.as_str()).collect();
    let results = oracle.crack(&hash_refs, early_exit);

    for result in &results {
        if result.matches.is_empty() {
            println!("{}: NOT FOUND", result.queried_hash);
        } else {
            for m in &result.matches {
                let plaintext = m.lookup_match.plaintext_lossy();
                match &m.lookup_match {
                    LookupMatch::Full { algorithm, .. } => {
                        println!(
                            "{}: {} [{}] ({})",
                            result.queried_hash,
                            plaintext,
                            m.table_label,
                            algorithm.name()
                        );
                    }
                    LookupMatch::Partial {
                        algorithm,
                        recomputed_hash,
                        ..
                    } => {
                        println!(
                            "{}: {} [{}] ({}, partial, full hash: {})",
                            result.queried_hash,
                            plaintext,
                            m.table_label,
                            algorithm.name(),
                            hex::encode(recomputed_hash)
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn cmd_algorithms() -> Result<()> {
    for name in hashing::list_algorithms() {
        println!("{name}");
    }
    Ok(())
}
