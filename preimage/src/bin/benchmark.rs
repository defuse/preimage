use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use humansize::{SizeFormatter, BINARY};
use indicatif::{ProgressBar, ProgressStyle};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use preimage::{get_algorithm, HashAlgorithm, IndexFile};

#[derive(Parser)]
#[command(
    name = "benchmark",
    about = "Benchmark preimage index build, sort, and lookup performance"
)]
struct Cli {
    /// Number of wordlist entries (suffixes: K=thousands, M=millions, G=billions)
    #[arg(long, value_parser = parse_entries)]
    entries: u64,

    /// Hash algorithm
    #[arg(short, long, default_value = "md5")]
    algorithm: String,

    /// Lookup threads
    #[arg(short, long, default_value = "1")]
    parallel: usize,

    /// Lookups per batch for latency tracking
    #[arg(short, long, default_value = "1000")]
    batch: usize,

    /// Seconds to run lookup benchmark
    #[arg(short, long, default_value = "10")]
    duration: u64,

    /// Sort buffer size (e.g. 256M, 4G)
    #[arg(short, long, default_value = "2G", value_parser = parse_memory_size)]
    memory: usize,

    /// Directory for generated files
    #[arg(long, default_value = "benchmark_data")]
    data_dir: PathBuf,

    /// Delete existing wordlist and index files before benchmarking
    #[arg(long)]
    clean: bool,
}

fn parse_entries(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('G') {
        (n, 1_000_000_000u64)
    } else if let Some(n) = s.strip_suffix('M') {
        (n, 1_000_000u64)
    } else if let Some(n) = s.strip_suffix('K') {
        (n, 1_000u64)
    } else {
        (s, 1u64)
    };

    let num: u64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid number: {num_str:?}"))?;

    num.checked_mul(multiplier)
        .ok_or_else(|| format!("entry count overflows u64: {s}"))
}

fn parse_memory_size(s: &str) -> Result<usize, String> {
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

fn main() {
    let cli = Cli::parse();

    let algorithm: &'static dyn HashAlgorithm =
        get_algorithm(&cli.algorithm).unwrap_or_else(|| {
            eprintln!("Unknown algorithm: {}", cli.algorithm);
            std::process::exit(1);
        });

    println!("=== Configuration ===");
    println!("Algorithm:    {}", cli.algorithm);
    println!("Entries:      {}", format_count(cli.entries));
    println!("Threads:      {}", cli.parallel);
    println!("Batch size:   {}", format_count(cli.batch as u64));
    println!("Duration:     {}s", cli.duration);
    println!();

    fs::create_dir_all(&cli.data_dir).expect("failed to create data directory");

    let wordlist_path = cli
        .data_dir
        .join(format!("{}_{}.txt", cli.algorithm, cli.entries));
    let index_path = cli
        .data_dir
        .join(format!("{}_{}.idx", cli.algorithm, cli.entries));

    if cli.clean {
        for path in [&wordlist_path, &index_path] {
            if path.exists() {
                fs::remove_file(path).expect("failed to remove file");
                println!("Cleaned:      {}", path.display());
            }
        }
    }

    println!("=== Data Preparation ===");

    // Phase A: Generate wordlist
    generate_wordlist(&wordlist_path, cli.entries);

    // Phase B: Build index
    let entry_count = build_index(algorithm, &wordlist_path, &index_path);

    // Phase C: Validate and sort index if needed
    sort_index(&index_path, entry_count, cli.memory);

    println!();

    // Phase D: Lookup benchmark
    run_lookup_benchmark(
        algorithm,
        &index_path,
        &wordlist_path,
        entry_count,
        cli.parallel,
        cli.batch,
        cli.duration,
    );
}

/// The Nth word in the wordlist, computable in O(1) without reading the file.
/// Seed a per-word RNG from the index to get variable-length alphanumeric strings.
fn nth_word(n: u64) -> String {
    use rand::distributions::Alphanumeric;
    let mut rng = SmallRng::seed_from_u64(n);
    let len = rng.gen_range(10..=20);
    (0..len).map(|_| rng.sample(Alphanumeric) as char).collect()
}

fn progress_bar(total: u64, msg: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .expect("valid template")
            .progress_chars("#>-"),
    );
    pb.set_message(msg.to_string());
    pb
}

fn file_size(path: &Path) -> String {
    let size = fs::metadata(path)
        .expect("failed to read file metadata")
        .len();
    SizeFormatter::new(size, BINARY).to_string()
}

fn generate_wordlist(path: &Path, entries: u64) {
    if path.exists() {
        println!(
            "Wordlist:     {} ({}, exists, skipped)",
            path.display(),
            file_size(path)
        );
        return;
    }

    let pb = progress_bar(entries, "Generating wordlist");

    let start = Instant::now();
    let file = fs::File::create(path).expect("failed to create wordlist file");
    let mut writer = BufWriter::new(file);

    for i in 0..entries {
        writeln!(writer, "{}", nth_word(i)).expect("failed to write word");
        if i % 100_000 == 0 {
            pb.set_position(i);
        }
    }
    writer.flush().expect("failed to flush wordlist");
    drop(writer);
    pb.finish_and_clear();

    let elapsed = start.elapsed();
    println!(
        "Wordlist:     {} ({}, {} entries, {:.2}s)",
        path.display(),
        file_size(path),
        format_count(entries),
        elapsed.as_secs_f64(),
    );
}

fn build_index(
    algorithm: &'static dyn HashAlgorithm,
    wordlist_path: &Path,
    index_path: &Path,
) -> u64 {
    if index_path.exists() {
        let index = IndexFile::open(index_path);
        let count = index.entry_count().expect("failed to read entry count");
        println!(
            "Index build:  {} ({}, exists, skipped)",
            index_path.display(),
            file_size(index_path)
        );
        return count;
    }

    let pb = progress_bar(0, "Building index");

    let start = Instant::now();
    let index = IndexFile::build(algorithm, wordlist_path, index_path, Some(&pb))
        .expect("failed to build index");
    pb.finish_and_clear();
    let elapsed = start.elapsed();

    let count = index.entry_count().expect("failed to read entry count");
    let secs = elapsed.as_secs_f64();
    let (rate, per_entry_us) = per_entry_stats(count, secs);

    println!(
        "Index build:  {:.2}s ({}, {} entries, {:.0} entries/sec, {:.2}us/entry)",
        secs,
        file_size(index_path),
        format_count(count),
        rate,
        per_entry_us,
    );

    count
}

fn sort_index(index_path: &Path, entry_count: u64, memory_bytes: usize) {
    let check_pb = progress_bar(entry_count, "Checking sort");
    let check_start = Instant::now();
    let index = IndexFile::open(index_path);
    let sorted = index
        .check_sorted(Some(&check_pb))
        .expect("failed to check sort status");
    check_pb.finish_and_clear();
    let check_elapsed = check_start.elapsed();
    let check_secs = check_elapsed.as_secs_f64();
    let (check_rate, check_per_entry_us) = per_entry_stats(entry_count, check_secs);

    println!(
        "Sort check:   {:.2}s ({} entries, {:.0} entries/sec, {:.2}us/entry)",
        check_secs,
        format_count(entry_count),
        check_rate,
        check_per_entry_us,
    );

    if sorted {
        println!("Index sort:   already sorted, skipped");
        return;
    }

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .expect("valid template"),
    );
    pb.enable_steady_tick(Duration::from_millis(100));

    let start = Instant::now();
    let index = IndexFile::open(index_path);
    index
        .sort(memory_bytes, Some(&pb))
        .expect("failed to sort index");
    pb.finish_and_clear();
    let elapsed = start.elapsed();

    let secs = elapsed.as_secs_f64();
    let (rate, per_entry_us) = per_entry_stats(entry_count, secs);

    println!(
        "Index sort:   {:.2}s ({} entries, {:.0} entries/sec, {:.2}us/entry)",
        secs,
        format_count(entry_count),
        rate,
        per_entry_us,
    );
}

/// Generate a random lookup hash on the fly. 50% chance of a real hash (hit),
/// 50% chance of random hex (miss). No pre-computed pool needed.
fn generate_lookup_hash(
    algorithm: &'static dyn HashAlgorithm,
    rng: &mut SmallRng,
    entry_count: u64,
    hash_hex_len: usize,
) -> String {
    if entry_count > 0 && rng.gen_bool(0.5) {
        // Real hash: pick a random word from the wordlist, hash it
        let idx = rng.gen_range(0..entry_count);
        let word = nth_word(idx);
        let hash = algorithm.hash(word.as_bytes()).expect("hash failed");
        hex::encode(&hash)
    } else {
        // Random hex string (almost certainly a miss)
        let hex_chars = b"0123456789abcdef";
        (0..hash_hex_len)
            .map(|_| hex_chars[rng.gen_range(0..16)] as char)
            .collect()
    }
}

fn run_lookup_benchmark(
    algorithm: &'static dyn HashAlgorithm,
    index_path: &Path,
    wordlist_path: &Path,
    entry_count: u64,
    parallel: usize,
    batch: usize,
    duration_secs: u64,
) {
    // Compute hash hex length from a sample hash
    let sample_hash = algorithm.hash(b"sample").expect("hash failed");
    let hash_hex_len = sample_hash.len() * 2;

    // Open lookup table
    let index = IndexFile::open(index_path);
    let table = Arc::new(
        index
            .into_lookup_table(algorithm, wordlist_path)
            .expect("failed to open lookup table"),
    );

    let stop = Arc::new(AtomicBool::new(false));
    let query_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let pb = ProgressBar::new(duration_secs);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}/{duration_precise}] [{bar:40.cyan/blue}] {msg}")
            .expect("valid template")
            .progress_chars("#>-"),
    );

    let wall_start = Instant::now();

    let all_latencies: Vec<Vec<Duration>> = std::thread::scope(|s| {
        // Timer thread: updates progress bar every 250ms, sets stop flag at end
        let stop_clone = Arc::clone(&stop);
        let query_count_clone = Arc::clone(&query_count);
        let pb_clone = pb.clone();
        s.spawn(move || {
            let start = Instant::now();
            let duration = Duration::from_secs(duration_secs);
            while start.elapsed() < duration {
                std::thread::sleep(Duration::from_millis(250));
                let elapsed = start.elapsed();
                let secs = elapsed.as_secs();
                pb_clone.set_position(secs.min(duration_secs));
                let queries = query_count_clone.load(Ordering::Relaxed);
                let qps = queries as f64 / elapsed.as_secs_f64();
                pb_clone.set_message(format!(
                    "{} queries, {:.0} queries/sec",
                    format_count(queries),
                    qps
                ));
            }
            stop_clone.store(true, Ordering::Relaxed);
        });

        // Worker threads
        let handles: Vec<_> = (0..parallel)
            .map(|thread_id| {
                let table = Arc::clone(&table);
                let stop = Arc::clone(&stop);
                let query_count = Arc::clone(&query_count);

                s.spawn(move || {
                    let mut rng = SmallRng::seed_from_u64(42 + thread_id as u64);
                    let mut latencies = Vec::new();

                    while !stop.load(Ordering::Relaxed) {
                        let batch_start = Instant::now();
                        for _ in 0..batch {
                            let hash_hex = generate_lookup_hash(
                                algorithm,
                                &mut rng,
                                entry_count,
                                hash_hex_len,
                            );
                            let _ = table.lookup(&hash_hex);
                        }
                        latencies.push(batch_start.elapsed());
                        query_count.fetch_add(batch as u64, Ordering::Relaxed);
                    }

                    latencies
                })
            })
            .collect();

        handles
            .into_iter()
            .map(|h| h.join().expect("worker thread panicked"))
            .collect()
    });

    pb.finish_and_clear();

    let wall_elapsed = wall_start.elapsed();
    let total_batches: usize = all_latencies.iter().map(|v| v.len()).sum();
    let total_lookups = total_batches as u64 * batch as u64;
    let throughput = total_lookups as f64 / wall_elapsed.as_secs_f64();

    println!("=== Lookup Results ===");
    println!("Wall time:      {:.2}s", wall_elapsed.as_secs_f64());
    println!(
        "Total queries:  {} ({} batches x {})",
        format_count(total_lookups),
        format_count(total_batches as u64),
        format_count(batch as u64),
    );
    println!("Throughput:     {:.0} queries/sec", throughput);

    // Compute latency stats
    let mut all: Vec<Duration> = all_latencies.into_iter().flatten().collect();
    if all.is_empty() {
        println!("\nNo batches completed in the given duration.");
        return;
    }

    all.sort();
    let min = all[0];
    let median = all[all.len() / 2];
    let p95 = all[(all.len() as f64 * 0.95) as usize];
    let p99 = all[((all.len() as f64 * 0.99) as usize).min(all.len() - 1)];

    println!();
    println!(
        "=== Batch Latency ({} queries/batch) ===",
        format_count(batch as u64)
    );
    println!("Min:     {}", format_duration(min));
    println!("Median:  {}", format_duration(median));
    println!("P95:     {}", format_duration(p95));
    println!("P99:     {}", format_duration(p99));
}

fn format_count(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

fn per_entry_stats(entry_count: u64, secs: f64) -> (f64, f64) {
    if entry_count == 0 || secs == 0.0 {
        (0.0, 0.0)
    } else {
        (
            entry_count as f64 / secs,
            secs * 1_000_000.0 / entry_count as f64,
        )
    }
}

fn format_duration(d: Duration) -> String {
    let us = d.as_micros();
    if us < 1_000 {
        format!("{us}us")
    } else if us < 1_000_000 {
        format!("{:.2}ms", us as f64 / 1_000.0)
    } else {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_lookup_hash_handles_zero_entries() {
        let algorithm = get_algorithm("md5").expect("md5 registered");
        let mut rng = SmallRng::seed_from_u64(42);

        for _ in 0..1024 {
            let hash = generate_lookup_hash(algorithm, &mut rng, 0, 32);
            assert_eq!(hash.len(), 32, "generated hash hex should be the requested length");
        }
    }

    #[test]
    fn test_sort_index_reused_existing_index_is_validated() {
        let dir = tempdir().expect("temp dir");
        let index_path = dir.path().join("words.idx");
        let wordlist_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("test_data")
            .join("words.txt");

        let algorithm = get_algorithm("md5").expect("md5 registered");
        let index = IndexFile::build(algorithm, &wordlist_path, &index_path, None).expect("build");
        let entry_count = index.entry_count().expect("entry count");
        assert!(
            !index.check_sorted(None).expect("check sorted"),
            "fixture should start unsorted"
        );

        let reused_count = build_index(algorithm, &wordlist_path, &index_path);
        assert_eq!(reused_count, entry_count);

        sort_index(&index_path, reused_count, 1024 * 1024);

        assert!(
            IndexFile::open(&index_path)
                .check_sorted(None)
                .expect("check sorted after benchmark setup"),
            "benchmark setup should reject or repair an existing unsorted index before lookup benchmarking"
        );
    }
}
