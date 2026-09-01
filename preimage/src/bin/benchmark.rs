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

use preimage::entry::HASH_PREFIX_LEN;

#[path = "shared/memory_size.rs"]
mod memory_size;
use memory_size::parse_memory_size;
use preimage::{get_algorithm, HashAlgorithm, IndexFile, LookupMatch};

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
    #[arg(short, long, default_value = "1", value_parser = parse_positive_usize)]
    parallel: usize,

    /// Lookups per batch for latency tracking
    #[arg(short, long, default_value = "1000", value_parser = parse_positive_usize)]
    batch: usize,

    /// Seconds to run lookup benchmark
    #[arg(short, long, default_value = "10", value_parser = parse_positive_u64)]
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

    let entries = num
        .checked_mul(multiplier)
        .ok_or_else(|| format!("entry count overflows u64: {s}"))?;

    if entries == 0 {
        return Err("entry count must be at least 1".to_string());
    }
    Ok(entries)
}

fn parse_positive_usize(s: &str) -> Result<usize, String> {
    let n: usize = s
        .trim()
        .parse()
        .map_err(|_| format!("invalid number: {s:?}"))?;
    if n == 0 {
        return Err("must be at least 1".to_string());
    }
    Ok(n)
}

fn parse_positive_u64(s: &str) -> Result<u64, String> {
    let n: u64 = s
        .trim()
        .parse()
        .map_err(|_| format!("invalid number: {s:?}"))?;
    if n == 0 {
        return Err("must be at least 1".to_string());
    }
    Ok(n)
}

fn main() {
    let cli = Cli::parse();

    let algorithm: &'static dyn HashAlgorithm =
        get_algorithm(&cli.algorithm).unwrap_or_else(|| {
            eprintln!("Unknown algorithm: {}", cli.algorithm);
            std::process::exit(1);
        });

    // An index entry stores an 8-byte hash prefix, and `LookupTable::lookup` rejects any
    // hex string shorter than that. Algorithms with a shorter digest (the 4-byte checksums:
    // adler32, crc32, crc32b, crc32c, fnv132, fnv1a32, joaat) therefore fail on every single
    // query, and benchmarking them would measure argument rejection rather than lookups.
    let digest_len = algorithm
        .hash(b"sample")
        .expect("sample input must be hashable")
        .len();
    if digest_len < HASH_PREFIX_LEN {
        eprintln!(
            "Cannot benchmark {}: its digest is {} bytes, but an index entry stores a \
             {}-byte prefix, so every lookup would be rejected before doing any work.",
            cli.algorithm, digest_len, HASH_PREFIX_LEN,
        );
        std::process::exit(1);
    }

    println!("=== Configuration ===");
    println!("Algorithm:    {}", cli.algorithm);
    println!("Entries:      {}", format_count(cli.entries));
    println!("Threads:      {}", cli.parallel);
    println!("Batch size:   {}", format_count(cli.batch as u64));
    println!("Duration:     {}s", cli.duration);
    println!();

    fs::create_dir_all(&cli.data_dir).expect("failed to create data directory");

    // Two of the 58 algorithm names contain a '/' ("sha512/224", "sha512/256"), which
    // Path::join would read as a directory separator into a directory nothing creates.
    let slug = filename_slug(&cli.algorithm);
    let wordlist_path = cli.data_dir.join(format!("{}_{}.txt", slug, cli.entries));
    let index_path = cli.data_dir.join(format!("{}_{}.idx", slug, cli.entries));

    if cli.clean {
        for path in [
            &wordlist_path,
            &index_path,
            &partial_path(&wordlist_path),
            &partial_path(&index_path),
        ] {
            if path.exists() {
                fs::remove_file(path).expect("failed to remove file");
                println!("Cleaned:      {}", path.display());
            }
        }
    }

    println!("=== Data Preparation ===");

    // Phase A: Generate wordlist
    generate_wordlist(&wordlist_path, cli.entries);

    // Phases B and C: build and sort the index. Both happen at a temporary path and the
    // result is renamed into place only once it is complete, so a file at `index_path` is
    // always a fully built, fully sorted index. That is what makes the "exists, skipped"
    // fast path safe: an interrupted run leaves behind only the partial file, which the
    // next run overwrites.
    let entry_count = prepare_index(algorithm, &wordlist_path, &index_path, cli.memory);

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

/// Turn an algorithm name into something safe to embed in a filename. Names come from
/// PHP and are not identifiers: `sha512/224` contains a path separator, `tiger160,3` and
/// `haval256,5` a comma, `MySQL4.1+` a dot and a plus.
fn filename_slug(algorithm_name: &str) -> String {
    algorithm_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// The sibling path a file is written to while it is still being produced. Nothing reads
/// it and the next run overwrites it, so an interrupted run cannot leave behind something
/// a later run mistakes for finished output.
fn partial_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .expect("generated paths always have a file name")
        .to_os_string();
    name.push(".partial");
    path.with_file_name(name)
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
    let partial = partial_path(path);
    let file = fs::File::create(&partial).expect("failed to create wordlist file");
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

    // Only now does the wordlist become visible under the name the cache checks for.
    fs::rename(&partial, path).expect("failed to move the finished wordlist into place");

    let elapsed = start.elapsed();
    println!(
        "Wordlist:     {} ({}, {} entries, {:.2}s)",
        path.display(),
        file_size(path),
        format_count(entries),
        elapsed.as_secs_f64(),
    );
}

/// Build and sort the index, publishing it at `index_path` only once it is complete.
///
/// The finished artifact is a *sorted* index, so both phases run against a temporary path
/// and the result is renamed into place at the end. A file at `index_path` is therefore
/// never partially built and never unsorted, which is what lets a later run reuse it
/// without re-checking. Returns the entry count.
fn prepare_index(
    algorithm: &'static dyn HashAlgorithm,
    wordlist_path: &Path,
    index_path: &Path,
    memory_bytes: usize,
) -> u64 {
    if index_path.exists() {
        let index = IndexFile::open(index_path);
        let count = index.entry_count().expect("failed to read entry count");
        println!(
            "Index build:  {} ({}, {} entries, exists, skipped)",
            index_path.display(),
            file_size(index_path),
            format_count(count),
        );
        println!("Sort check:   skipped (a cached index is sorted by construction)");
        println!("Index sort:   skipped (a cached index is sorted by construction)");
        return count;
    }

    let partial = partial_path(index_path);
    let count = build_index(algorithm, wordlist_path, &partial);
    sort_index(&partial, count, memory_bytes);
    fs::rename(&partial, index_path).expect("failed to move the finished index into place");

    count
}

/// Returns the entry count.
fn build_index(
    algorithm: &'static dyn HashAlgorithm,
    wordlist_path: &Path,
    index_path: &Path,
) -> u64 {
    let pb = progress_bar(0, "Building index");

    let start = Instant::now();
    let index = IndexFile::build(algorithm, wordlist_path, index_path, Some(&pb))
        .expect("failed to build index");
    pb.finish_and_clear();
    let elapsed = start.elapsed();

    let count = index.entry_count().expect("failed to read entry count");
    let secs = elapsed.as_secs_f64();

    println!(
        "Index build:  {:.2}s ({}, {} entries, {}, {})",
        secs,
        file_size(index_path),
        format_count(count),
        format_rate(count, secs),
        format_per_entry(count, secs),
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

    println!(
        "Sort check:   {:.2}s ({} entries, {}, {})",
        check_secs,
        format_count(entry_count),
        format_rate(entry_count, check_secs),
        format_per_entry(entry_count, check_secs),
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

    println!(
        "Index sort:   {:.2}s ({} entries, {}, {})",
        secs,
        format_count(entry_count),
        format_rate(entry_count, secs),
        format_per_entry(entry_count, secs),
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
    if rng.gen_bool(0.5) {
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

    let results: Vec<(Vec<Duration>, Outcomes)> = std::thread::scope(|s| {
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
                    let mut outcomes = Outcomes::default();

                    while !stop.load(Ordering::Relaxed) {
                        let batch_start = Instant::now();
                        for _ in 0..batch {
                            let hash_hex = generate_lookup_hash(
                                algorithm,
                                &mut rng,
                                entry_count,
                                hash_hex_len,
                            );
                            // Consume the result. A discarded Err looks exactly like a
                            // successful lookup in the timings, which is how a run where
                            // every single query was rejected could report a throughput
                            // figure at all.
                            outcomes.record(table.lookup(&hash_hex));
                        }
                        latencies.push(batch_start.elapsed());
                        query_count.fetch_add(batch as u64, Ordering::Relaxed);
                    }

                    (latencies, outcomes)
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
    let (all_latencies, per_thread_outcomes): (Vec<Vec<Duration>>, Vec<Outcomes>) =
        results.into_iter().unzip();
    let outcomes = per_thread_outcomes
        .into_iter()
        .fold(Outcomes::default(), Outcomes::merge);
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
    println!(
        "Outcomes:       {} hits, {} misses, {} errors",
        format_count(outcomes.hits),
        format_count(outcomes.misses),
        format_count(outcomes.errors),
    );

    // A benchmark that measured no lookups is worse than no benchmark, because the
    // throughput and latency figures above look ordinary either way. Say so loudly.
    if outcomes.errors > 0 {
        eprintln!(
            "\nWARNING: {} of {} lookups returned an error. Those queries did no lookup \
             work, so the throughput and latency figures above are not measurements of \
             the index.",
            format_count(outcomes.errors),
            format_count(outcomes.total()),
        );
    }
    // generate_lookup_hash aims for a 50/50 split of real hashes and random hex, so a
    // hit rate far from 50% means the queries are not exercising the intended mix.
    let hit_rate = outcomes.hit_rate();
    if outcomes.total() > 0 && !(0.3..=0.7).contains(&hit_rate) {
        eprintln!(
            "\nWARNING: hit rate is {:.1}%, but the query generator aims for 50%. The \
             workload is not the intended half-hit/half-miss mix.",
            hit_rate * 100.0,
        );
    }

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

/// What the lookups actually did, so the throughput figure can be checked against real
/// work rather than reported on faith.
#[derive(Default, Clone, Copy)]
struct Outcomes {
    hits: u64,
    misses: u64,
    errors: u64,
}

impl Outcomes {
    fn record<E>(&mut self, result: Result<Vec<LookupMatch>, E>) {
        match result {
            Ok(matches) if matches.is_empty() => self.misses += 1,
            Ok(_) => self.hits += 1,
            Err(_) => self.errors += 1,
        }
    }

    fn merge(self, other: Self) -> Self {
        Self {
            hits: self.hits + other.hits,
            misses: self.misses + other.misses,
            errors: self.errors + other.errors,
        }
    }

    fn total(&self) -> u64 {
        self.hits + self.misses + self.errors
    }

    fn hit_rate(&self) -> f64 {
        if self.total() == 0 {
            0.0
        } else {
            self.hits as f64 / self.total() as f64
        }
    }
}

/// Entries per second, or `n/a` when there is nothing to divide by. An index can legally
/// end up empty — every word rejected by the algorithm, for instance — and `inf` in a
/// results table is worse than an honest blank.
fn format_rate(count: u64, secs: f64) -> String {
    if count == 0 || secs <= 0.0 {
        "n/a entries/sec".to_string()
    } else {
        format!("{:.0} entries/sec", count as f64 / secs)
    }
}

fn format_per_entry(count: u64, secs: f64) -> String {
    if count == 0 {
        "n/a us/entry".to_string()
    } else {
        format!("{:.2}us/entry", secs * 1_000_000.0 / count as f64)
    }
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
    use preimage::ALGORITHM_NAMES;

    #[test]
    fn every_algorithm_name_yields_a_single_path_component() {
        for name in ALGORITHM_NAMES {
            let path = Path::new("benchmark_data").join(format!("{}_1000.idx", filename_slug(name)));
            assert_eq!(
                path.components().count(),
                2,
                "{name} produced a nested path: {}",
                path.display()
            );
        }
    }

    #[test]
    fn filename_slug_replaces_the_characters_php_names_actually_contain() {
        assert_eq!(filename_slug("sha512/224"), "sha512_224");
        assert_eq!(filename_slug("tiger160,3"), "tiger160_3");
        assert_eq!(filename_slug("haval256,5"), "haval256_5");
        assert_eq!(filename_slug("MySQL4.1+"), "MySQL4_1_");
        assert_eq!(filename_slug("md5"), "md5");
    }

    #[test]
    fn partial_path_is_a_sibling_of_the_finished_file() {
        let finished = Path::new("benchmark_data/md5_1000.idx");
        assert_eq!(
            partial_path(finished),
            Path::new("benchmark_data/md5_1000.idx.partial")
        );
    }

    #[test]
    fn zero_valued_arguments_are_rejected() {
        assert_eq!(parse_entries("0"), Err("entry count must be at least 1".to_string()));
        assert_eq!(parse_entries("0M"), Err("entry count must be at least 1".to_string()));
        assert_eq!(parse_positive_usize("0"), Err("must be at least 1".to_string()));
        assert_eq!(parse_positive_u64("0"), Err("must be at least 1".to_string()));

        assert_eq!(parse_entries("1"), Ok(1));
        assert_eq!(parse_entries("2M"), Ok(2_000_000));
        assert_eq!(parse_positive_usize("1000"), Ok(1000));
        assert_eq!(parse_positive_u64("10"), Ok(10));
    }

    #[test]
    fn rates_are_not_infinite_when_there_is_nothing_to_divide_by() {
        assert_eq!(format_rate(0, 1.5), "n/a entries/sec");
        assert_eq!(format_per_entry(0, 1.5), "n/a us/entry");
        assert_eq!(format_rate(1000, 0.0), "n/a entries/sec");
        assert_eq!(format_rate(1000, 2.0), "500 entries/sec");
    }

    #[test]
    fn outcomes_separate_hits_misses_and_errors() {
        let mut outcomes = Outcomes::default();
        outcomes.record(Ok::<_, ()>(vec![]));
        outcomes.record(Err::<Vec<LookupMatch>, _>(()));
        assert_eq!((outcomes.hits, outcomes.misses, outcomes.errors), (0, 1, 1));
        assert_eq!(outcomes.total(), 2);
        assert_eq!(outcomes.hit_rate(), 0.0);

        let merged = outcomes.merge(Outcomes {
            hits: 2,
            misses: 0,
            errors: 0,
        });
        assert_eq!((merged.hits, merged.misses, merged.errors), (2, 1, 1));
        assert_eq!(merged.hit_rate(), 0.5);
    }
}
