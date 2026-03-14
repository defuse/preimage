use crate::HashAlgorithm;
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;

/// LAN Manager hash.
///
/// Uppercase input, pad to 14 bytes, split into two 7-byte halves,
/// expand each to an 8-byte DES key, DES-ECB encrypt `"KGS!@#$%"`,
/// concatenate the two 8-byte ciphertexts.
pub struct Lm;

const KGS_CONSTANT: [u8; 8] = *b"KGS!@#$%";

impl HashAlgorithm for Lm {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        // Uppercase and truncate to 14 bytes, then pad with nulls.
        // The PHP code uses strtoupper(substr($string, 0, 14)) which operates
        // on bytes, so we do the same — this is ASCII uppercasing only.
        let mut password = [0u8; 14];
        let upper: Vec<u8> = input.iter().map(|&b| b.to_ascii_uppercase()).collect();
        let copy_len = upper.len().min(14);
        password[..copy_len].copy_from_slice(&upper[..copy_len]);

        let p1 = lm_des_encrypt(&password[0..7]);
        let p2 = lm_des_encrypt(&password[7..14]);

        let mut result = Vec::with_capacity(16);
        result.extend_from_slice(&p1);
        result.extend_from_slice(&p2);
        Some(result)
    }

    fn name(&self) -> &str {
        "LM"
    }
}

/// Expand 7 bytes to an 8-byte DES key (with parity bits) and encrypt the KGS constant.
fn lm_des_encrypt(half: &[u8]) -> [u8; 8] {
    assert_eq!(half.len(), 7, "LM half must be exactly 7 bytes");

    // Expand 56 bits to 64 bits matching the PHP/C key schedule exactly.
    // Each output byte uses 7 data bits and 1 parity bit (LSB).
    let mut key = [0u8; 8];
    key[0] = half[0] & 0xFE;
    key[1] = ((half[0] << 7) | (half[1] >> 1)) & 0xFE;
    key[2] = ((half[1] << 6) | (half[2] >> 2)) & 0xFE;
    key[3] = ((half[2] << 5) | (half[3] >> 3)) & 0xFE;
    key[4] = ((half[3] << 4) | (half[4] >> 4)) & 0xFE;
    key[5] = ((half[4] << 3) | (half[5] >> 5)) & 0xFE;
    key[6] = ((half[5] << 2) | (half[6] >> 6)) & 0xFE;
    key[7] = (half[6] << 1) & 0xFE;

    // Set odd parity for each byte (matching openssl DES key parity).
    for byte in &mut key {
        let ones = byte.count_ones();
        if ones % 2 == 0 {
            *byte |= 1;
        }
    }

    let cipher = Des::new_from_slice(&key).expect("DES key is always 8 bytes");
    let mut block = KGS_CONSTANT.into();
    cipher.encrypt_block(&mut block);
    block.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lm_empty() {
        let hash = Lm.hash(b"").expect("LM should not fail");
        assert_eq!(hex::encode(&hash), "aad3b435b51404eeaad3b435b51404ee");
    }

    #[test]
    fn test_lm_password() {
        let hash = Lm.hash(b"PASSWORD").expect("LM should not fail");
        assert_eq!(hex::encode(&hash), "e52cac67419a9a224a3b108f3fa6cb6d");
    }

    #[test]
    fn test_lm_lowercase_uppercased() {
        // LM uppercases the input, so "password" == "PASSWORD"
        let lower = Lm.hash(b"password").expect("should not fail");
        let upper = Lm.hash(b"PASSWORD").expect("should not fail");
        assert_eq!(lower, upper);
    }

    #[test]
    fn test_lm_hello() {
        let hash = Lm.hash(b"hello").expect("should not fail");
        assert_eq!(hex::encode(&hash), "fda95fbeca288d44aad3b435b51404ee");
    }

    #[test]
    fn test_lm_emoji() {
        // LM treats emoji as raw bytes, uppercases byte-by-byte (no-op for high bytes)
        let hash = Lm.hash("😀".as_bytes()).expect("should not fail");
        assert_eq!(hex::encode(&hash), "727f6a04bfb4f99faad3b435b51404ee");
    }

    #[test]
    fn test_lm_truncation() {
        // LM only uses first 14 characters
        let short = Lm.hash(b"12345678901234").expect("should not fail");
        let long = Lm.hash(b"12345678901234extra").expect("should not fail");
        assert_eq!(short, long);
    }
}
