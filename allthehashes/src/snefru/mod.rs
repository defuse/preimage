//! Snefru hash algorithm implementation.
//!
//! WARNING: Not for cryptographic use. This crate deliberately includes insecure
//! hash functions, and none of these implementations has had a security review.
//! It is for password cracking and interoperability with old systems — do not use
//! it to protect anything.
//!
//! Snefru is a cryptographic hash function designed by Ralph Merkle in 1990.
//! This implementation produces a 256-bit (32-byte) digest using 8 rounds,
//! matching PHP's hash('snefru') and hash('snefru256') output exactly.

mod tables;

use tables::SBOX;

/// Block size in bytes (256 bits = 32 bytes)
const BLOCK_SIZE: usize = 32;

/// Digest size in bytes (256 bits = 32 bytes)
const DIGEST_SIZE: usize = 32;

/// Number of rounds
const ROUNDS: usize = 8;

/// Rotation shifts for each sub-round
const SHIFTS: [u32; 4] = [16, 8, 16, 24];

/// Snefru hash context
struct SnefruContext {
    /// Hash state (16 x 32-bit words)
    state: [u32; 16],
    /// Bit count (low, high)
    count: [u32; 2],
    /// Buffer for partial blocks
    buffer: [u8; BLOCK_SIZE],
    /// Number of bytes in buffer
    buffer_len: usize,
}

/// Add `byte_len` bytes' worth of bits to the 64-bit message-length counter.
///
/// `count[0]` is the high word and `count[1]` the low word: `finalize` writes them
/// into `state[14]` and `state[15]`, which is the 64-bit message-length field Snefru's
/// final block encodes. Merkle-Damgård strengthening only works if that field is the
/// true bit length, so both halves have to be maintained.
///
/// `byte_len * 8` is a 64-bit quantity. Its low 32 bits go in the low word, and the
/// three bits the shift pushes past a 32-bit word — everything at or above 2^29 bytes
/// — belong in the high word. The high term used to be missing entirely, and the only
/// carry performed was the one out of the *accumulation*, which cannot recover bits
/// already discarded by the multiplication. The length field therefore wrapped every
/// 512 MiB, so a 512 MiB input hashed as though it were zero-length. HAVAL, in this
/// same crate, carries it correctly; this is the line Snefru was missing.
fn add_bit_length(count: &mut [u32; 2], byte_len: usize) {
    // Widen before shifting: `(byte_len as u32) << 3` would truncate to 32 bits first
    // and lose the high bits of any input above 4 GiB.
    let bit_len_low = ((byte_len as u64) << 3) as u32;

    let (low, overflow) = count[1].overflowing_add(bit_len_low);
    count[1] = low;
    if overflow {
        count[0] = count[0].wrapping_add(1);
    }
    count[0] = count[0].wrapping_add((byte_len >> 29) as u32);
}

impl SnefruContext {
    fn new() -> Self {
        Self {
            state: [0u32; 16],
            count: [0u32; 2],
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        add_bit_length(&mut self.count, data.len());

        let mut offset = 0;

        // If we have buffered data, try to complete a block
        if self.buffer_len > 0 {
            let needed = BLOCK_SIZE - self.buffer_len;
            if data.len() >= needed {
                self.buffer[self.buffer_len..].copy_from_slice(&data[..needed]);
                self.transform(&self.buffer.clone());
                offset = needed;
                self.buffer_len = 0;
            } else {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
        }

        // Process complete blocks
        while offset + BLOCK_SIZE <= data.len() {
            self.transform(&data[offset..offset + BLOCK_SIZE]);
            offset += BLOCK_SIZE;
        }

        // Buffer remaining data
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    fn transform(&mut self, block: &[u8]) {
        // Load block into state[8..16] in big-endian format
        for i in 0..8 {
            let j = i * 4;
            self.state[8 + i] =
                u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
        }

        // Apply Snefru function
        snefru_block(&mut self.state);

        // Clear the input portion
        for i in 8..16 {
            self.state[i] = 0;
        }
    }

    fn finalize(mut self) -> [u8; DIGEST_SIZE] {
        // Process any remaining buffered data
        if self.buffer_len > 0 {
            // Zero-pad the buffer
            for i in self.buffer_len..BLOCK_SIZE {
                self.buffer[i] = 0;
            }
            self.transform(&self.buffer.clone());
        }

        // Append bit count and do final transformation
        self.state[14] = self.count[0];
        self.state[15] = self.count[1];
        snefru_block(&mut self.state);

        // Extract digest from state[0..8] in big-endian format
        let mut digest = [0u8; DIGEST_SIZE];
        for i in 0..8 {
            let bytes = self.state[i].to_be_bytes();
            digest[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }

        digest
    }
}

/// Core Snefru block function
///
/// Operates on 16 32-bit words (512-bit state).
/// Uses 8 iterations with 4 sub-rounds each.
fn snefru_block(state: &mut [u32; 16]) {
    let mut b = *state;

    for round in 0..ROUNDS {
        let t0 = &SBOX[2 * round];
        let t1 = &SBOX[2 * round + 1];

        for &shift in &SHIFTS {
            // Apply S-box lookups and XOR operations
            macro_rules! sbox_round {
                ($l:expr, $c:expr, $n:expr, $table:expr) => {{
                    let sbe = $table[(b[$c] & 0xff) as usize];
                    b[$l] ^= sbe;
                    b[$n] ^= sbe;
                }};
            }

            sbox_round!(15, 0, 1, t0);
            sbox_round!(0, 1, 2, t0);
            sbox_round!(1, 2, 3, t1);
            sbox_round!(2, 3, 4, t1);
            sbox_round!(3, 4, 5, t0);
            sbox_round!(4, 5, 6, t0);
            sbox_round!(5, 6, 7, t1);
            sbox_round!(6, 7, 8, t1);
            sbox_round!(7, 8, 9, t0);
            sbox_round!(8, 9, 10, t0);
            sbox_round!(9, 10, 11, t1);
            sbox_round!(10, 11, 12, t1);
            sbox_round!(11, 12, 13, t0);
            sbox_round!(12, 13, 14, t0);
            sbox_round!(13, 14, 15, t1);
            sbox_round!(14, 15, 0, t1);

            // Rotate all state words
            for word in &mut b {
                *word = word.rotate_right(shift);
            }
        }
    }

    // XOR transformed values back into state
    state[0] ^= b[15];
    state[1] ^= b[14];
    state[2] ^= b[13];
    state[3] ^= b[12];
    state[4] ^= b[11];
    state[5] ^= b[10];
    state[6] ^= b[9];
    state[7] ^= b[8];
}

/// Compute Snefru-256 hash of the input data.
pub fn snefru256(data: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut ctx = SnefruContext::new();
    ctx.update(data);
    ctx.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors verified against PHP's hash() function (defuse.ca/checksums.htm)

    #[test]
    fn test_snefru_empty() {
        assert_eq!(
            hex::encode(snefru256(b"")),
            "8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881"
        );
    }

    #[test]
    fn test_snefru_hello() {
        assert_eq!(
            hex::encode(snefru256(b"hello")),
            "7c5f22b1a92d9470efea37ec6ed00b2357a4ce3c41aa6e28e3b84057465dbb56"
        );
    }

    #[test]
    fn test_snefru_emoji() {
        assert_eq!(
            hex::encode(snefru256("😀".as_bytes())),
            "85a8a094db2c550e8c3bc0aca6066b93108f9b702052e3e2c08abec4557b363e"
        );
    }

    // === Multi-block tests (block size = 32 bytes) ===

    #[test]
    fn test_snefru_31_bytes() {
        assert_eq!(
            hex::encode(snefru256(&[b'a'; 31])),
            "96bb2b81b3aff11a4d672b23f600f6965c138276ead7d089369deaa9258988e7"
        );
    }

    #[test]
    fn test_snefru_32_bytes() {
        assert_eq!(
            hex::encode(snefru256(&[b'a'; 32])),
            "dbc6238cc321aecba8f057213c3a605d74f21ec352e2183bc3b3853064ffa732"
        );
    }

    #[test]
    fn test_snefru_33_bytes() {
        assert_eq!(
            hex::encode(snefru256(&[b'a'; 33])),
            "7a1133846080dd68d6842df39c86f961925605679bad4ffae07118482b6031fa"
        );
    }

    #[test]
    fn test_snefru_63_bytes() {
        assert_eq!(
            hex::encode(snefru256(&[b'a'; 63])),
            "c54c602ac46383716ee7200a76c9c90a7b435bbe31d13f04e0b00a7ea5c347fa"
        );
    }

    #[test]
    fn test_snefru_64_bytes() {
        assert_eq!(
            hex::encode(snefru256(&[b'a'; 64])),
            "7a8539c59e192e8d70b1ab82aa86a1b54560d42020bda4e00ddd6d048fe3bcaa"
        );
    }

    #[test]
    fn test_snefru_65_bytes() {
        assert_eq!(
            hex::encode(snefru256(&[b'a'; 65])),
            "c41657a506e5f10abf57a6742668ea142b27acf759c4c29c9b2f9282c4415432"
        );
    }

    #[test]
    fn test_snefru_1000_bytes() {
        assert_eq!(
            hex::encode(snefru256(&[b'a'; 1000])),
            "c5795bac1192bdea5a9dbe735211f890aef23b92687b6002d1938a7876e049c3"
        );
    }

    // === Binary pattern tests ===

    #[test]
    fn test_snefru_64_0xff() {
        assert_eq!(
            hex::encode(snefru256(&[0xFFu8; 64])),
            "a85110ae4dffe3765c7fadc0579d640c5675004fa3819a48e92d3bd1746d8785"
        );
    }

    #[test]
    fn test_snefru_128_0xff() {
        assert_eq!(
            hex::encode(snefru256(&[0xFFu8; 128])),
            "991622122962717b822e08653b1f4fbae53fa7a3eb3583ba423b6782b4d05881"
        );
    }
}

#[cfg(test)]
mod bit_length_tests {
    use super::add_bit_length;

    /// The counter must encode the true 64-bit message length. The high word used to
    /// be left at zero for any single update, so the field wrapped every 512 MiB and a
    /// 512 MiB message was indistinguishable from an empty one -- a Merkle-Damgård
    /// length-extension footgun, and a digest that disagrees with every other Snefru.
    ///
    /// Asserted on the counter rather than on a digest because reproducing it end to
    /// end means hashing half a gigabyte through a deliberately slow function.
    #[test]
    fn high_word_carries_above_512_mib() {
        let mut count = [0u32; 2];
        add_bit_length(&mut count, 1 << 29); // 512 MiB
        assert_eq!(count, [1, 0], "2^29 bytes is exactly 2^32 bits: high 1, low 0");

        let mut count = [0u32; 2];
        add_bit_length(&mut count, (1 << 29) - 1);
        assert_eq!(count, [0, 0xFFFF_FFF8], "one byte short must not carry");

        let mut count = [0u32; 2];
        add_bit_length(&mut count, 1 << 30);
        assert_eq!(count, [2, 0]);
    }

    /// Above 4 GiB the length must not be truncated to 32 bits before the shift.
    #[test]
    fn lengths_above_four_gib_are_not_truncated() {
        let mut count = [0u32; 2];
        add_bit_length(&mut count, 1usize << 32);
        assert_eq!(count, [8, 0], "2^32 bytes is 2^35 bits");

        // A length whose low 32 bits are zero must still register in the high word;
        // truncating first would have recorded nothing at all.
        let mut count = [0u32; 2];
        add_bit_length(&mut count, 1usize << 35);
        assert_eq!(count, [1 << 6, 0]);
    }

    #[test]
    fn small_lengths_are_unchanged() {
        for (bytes, expected_low) in [(0usize, 0u32), (1, 8), (55, 440), (64, 512)] {
            let mut count = [0u32; 2];
            add_bit_length(&mut count, bytes);
            assert_eq!(count, [0, expected_low], "{bytes} bytes");
        }
    }

    /// Repeated updates accumulate, and a carry out of the low word reaches the high
    /// word -- the one carry the old code did perform.
    #[test]
    fn accumulation_carries_between_words() {
        let mut count = [0u32; 2];
        add_bit_length(&mut count, (1 << 29) - 1); // low = 0xFFFF_FFF8
        add_bit_length(&mut count, 1); // +8 bits -> wraps to 0
        assert_eq!(count, [1, 0]);
    }
}
