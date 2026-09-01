//! Parsing for the `--memory` budget, shared by both binaries via `#[path]` so the two
//! cannot drift apart.

/// Parse a memory budget written as `256M`, `1.5G` or `4096K` into a byte count.
///
/// Deliberately strict. This number decides how large a buffer the sorter allocates
/// (`sorter.rs`: `memory_bytes / ENTRY_SIZE`), so anything that is not a real byte count
/// has to be refused at the command line rather than quietly turned into one.
///
/// `f64::from_str` accepts `inf`, `infinity` and `nan`, and the float-to-int `as` cast
/// that follows converts those to the two worst answers available: `inf` saturates to
/// `usize::MAX`, so the sorter tries to hold the whole index in RAM, and `nan` casts to
/// `0`, giving a zero-entry buffer. Both are rejected here, along with a value so large
/// it cannot be addressed and one that rounds down to nothing.
pub fn parse_memory_size(s: &str) -> Result<usize, String> {
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

    // Ordered before the sign check on purpose: `NAN < 0.0` is false, like every NaN
    // comparison, so a negativity test alone lets NaN through.
    if !num.is_finite() {
        return Err(format!(
            "memory size must be a finite number, not {num_str:?}"
        ));
    }

    if num < 0.0 {
        return Err("memory size cannot be negative".to_string());
    }

    let bytes = num * multiplier as f64;

    // `usize::MAX as f64` rounds up to 2^64, so this rejects exactly the values that
    // would saturate on the cast below.
    if bytes >= usize::MAX as f64 {
        return Err(format!("memory size {s:?} is too large to address"));
    }

    let bytes = bytes as usize;
    if bytes == 0 {
        return Err("memory size must be at least 1 byte".to_string());
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_ordinary_forms() {
        assert_eq!(parse_memory_size("1K"), Ok(1024));
        assert_eq!(parse_memory_size("256M"), Ok(256 * 1024 * 1024));
        assert_eq!(parse_memory_size("2G"), Ok(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_memory_size("1.5G"), Ok(1536 * 1024 * 1024));
        assert_eq!(parse_memory_size("  4G  "), Ok(4 * 1024 * 1024 * 1024));
        // Whitespace between the number and its suffix is tolerated too, because the
        // number is trimmed after the suffix is stripped. Asserted to pin it, not
        // because anyone types it.
        assert_eq!(parse_memory_size("2 G"), Ok(2 * 1024 * 1024 * 1024));
    }

    /// The bug this function was rewritten for. `inf` used to return `usize::MAX` and
    /// `nan` used to return `0`, neither with any complaint.
    #[test]
    fn rejects_infinity_and_nan_whatever_their_spelling() {
        for (input, number) in [
            ("infK", "inf"),
            ("INFM", "INF"),
            ("infinityG", "infinity"),
            ("+infG", "+inf"),
            ("-infG", "-inf"),
            ("nanK", "nan"),
            ("NaNM", "NaN"),
            ("-nanG", "-nan"),
        ] {
            assert_eq!(
                parse_memory_size(input),
                Err(format!(
                    "memory size must be a finite number, not {number:?}"
                )),
                "{input} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_negative_sizes() {
        assert_eq!(
            parse_memory_size("-1G"),
            Err("memory size cannot be negative".to_string())
        );
        assert_eq!(
            parse_memory_size("-0.5M"),
            Err("memory size cannot be negative".to_string())
        );
    }

    /// A finite number can still be too big: the product overflows f64 to infinity, and
    /// the cast would saturate to `usize::MAX` exactly as `inf` did.
    #[test]
    fn rejects_sizes_that_do_not_fit_in_a_usize() {
        assert_eq!(
            parse_memory_size("1e300G"),
            Err("memory size \"1e300G\" is too large to address".to_string())
        );
        assert_eq!(
            parse_memory_size("18446744073709551616K"),
            Err("memory size \"18446744073709551616K\" is too large to address".to_string())
        );
    }

    /// A zero-byte budget gives the sorter a zero-entry buffer, which can never make
    /// progress. `-0` reaches here too: it passes the sign check, since `-0.0 < 0.0` is
    /// false.
    #[test]
    fn rejects_sizes_that_round_down_to_nothing() {
        for input in ["0G", "0M", "0K", "-0G", "0.0000001K"] {
            assert_eq!(
                parse_memory_size(input),
                Err("memory size must be at least 1 byte".to_string()),
                "{input} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_a_missing_or_unknown_suffix() {
        for input in ["1024", "1024B", "4g", ""] {
            assert_eq!(
                parse_memory_size(input),
                Err("missing suffix: use K, M, or G (e.g. 256M, 4G)".to_string()),
                "{input} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_a_number_it_cannot_parse() {
        assert_eq!(
            parse_memory_size("abcG"),
            Err("invalid number: \"abc\"".to_string())
        );
        assert_eq!(
            parse_memory_size("1.2.3M"),
            Err("invalid number: \"1.2.3\"".to_string())
        );
    }
}
