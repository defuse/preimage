//! HAVAL hash algorithm implementation.
//! THIS IMPLEMENTATION HAS NOT BEEN AUDITED! DO NOT RELY ON IT FOR SECURITY!
//!
//! HAVAL is a cryptographic hash function designed by Yuliang Zheng, Josef Pieprzyk,
//! and Jennifer Seberry in 1992. It supports:
//! - Variable output sizes: 128, 160, 192, 224, 256 bits
//! - Variable number of passes: 3, 4, or 5
//!
//! This implementation matches PHP's hash() function output exactly.
//!
//! Note: HAVAL is considered weak by modern standards and should not be used
//! for security-critical applications.

/// Initial state values
const D0: [u32; 8] = [
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
];

/// Round constants for pass 2
const K2: [u32; 32] = [
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C, 0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    0x9216D5D9, 0x8979FB1B, 0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96,
    0xBA7C9045, 0xF12C7F99, 0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69,
    0xA458FEA3, 0xF4933D7E, 0x0D95748F, 0x728EB658, 0x718BCD58, 0x82154AEE, 0x7B54A41D, 0xC25A59B5,
];

/// Round constants for pass 3
const K3: [u32; 32] = [
    0x9C30D539, 0x2AF26013, 0xC5D1B023, 0x286085F0, 0xCA417918, 0xB8DB38EF, 0x8E79DCB0, 0x603A180E,
    0x6C9E0E8B, 0xB01E8A3E, 0xD71577C1, 0xBD314B27, 0x78AF2FDA, 0x55605C60, 0xE65525F3, 0xAA55AB94,
    0x57489862, 0x63E81440, 0x55CA396A, 0x2AAB10B6, 0xB4CC5C34, 0x1141E8CE, 0xA15486AF, 0x7C72E993,
    0xB3EE1411, 0x636FBC2A, 0x2BA9C55D, 0x741831F6, 0xCE5C3E16, 0x9B87931E, 0xAFD6BA33, 0x6C24CF5C,
];

/// Round constants for pass 4
const K4: [u32; 32] = [
    0x7A325381, 0x28958677, 0x3B8F4898, 0x6B4BB9AF, 0xC4BFE81B, 0x66282193, 0x61D809CC, 0xFB21A991,
    0x487CAC60, 0x5DEC8032, 0xEF845D5D, 0xE98575B1, 0xDC262302, 0xEB651B88, 0x23893E81, 0xD396ACC5,
    0x0F6D6FF3, 0x83F44239, 0x2E0B4482, 0xA4842004, 0x69C8F04A, 0x9E1F9B5E, 0x21C66842, 0xF6E96C9A,
    0x670C9C61, 0xABD388F0, 0x6A51A0D2, 0xD8542F68, 0x960FA728, 0xAB5133A3, 0x6EEF0B6C, 0x137A3BE4,
];

/// Round constants for pass 5
const K5: [u32; 32] = [
    0xBA3BF050, 0x7EFB2A98, 0xA1F1651D, 0x39AF0176, 0x66CA593E, 0x82430E88, 0x8CEE8619, 0x456F9FB4,
    0x7D84A5C3, 0x3B8B5EBE, 0xE06F75D8, 0x85C12073, 0x401A449F, 0x56C16AA6, 0x4ED3AA62, 0x363F7706,
    0x1BFEDF72, 0x429B023D, 0x37D0D724, 0xD00A1248, 0xDB0FEAD3, 0x49F1C09B, 0x075372C9, 0x80991B7B,
    0x25D479D8, 0xF6E8DEF7, 0xE3FE501A, 0xB6794C3B, 0x976CE0BD, 0x04C006BA, 0xC1A94FB6, 0x409F60C4,
];

/// Message word index permutation for pass 2
const I2: [usize; 32] = [
    5, 14, 26, 18, 11, 28, 7, 16, 0, 23, 20, 22, 1, 10, 4, 8,
    30, 3, 21, 9, 17, 24, 29, 6, 19, 12, 15, 13, 2, 25, 31, 27,
];

/// Message word index permutation for pass 3
const I3: [usize; 32] = [
    19, 9, 4, 20, 28, 17, 8, 22, 29, 14, 25, 12, 24, 30, 16, 26,
    31, 15, 7, 3, 1, 0, 18, 27, 13, 6, 21, 10, 23, 11, 5, 2,
];

/// Message word index permutation for pass 4
const I4: [usize; 32] = [
    24, 4, 0, 14, 2, 7, 28, 23, 26, 6, 30, 20, 18, 25, 19, 3,
    22, 11, 31, 21, 8, 27, 12, 9, 1, 29, 5, 15, 17, 10, 16, 13,
];

/// Message word index permutation for pass 5
const I5: [usize; 32] = [
    27, 3, 21, 26, 17, 11, 20, 29, 19, 0, 12, 7, 13, 8, 31, 10,
    5, 9, 14, 30, 18, 6, 28, 24, 2, 23, 16, 22, 4, 1, 25, 15,
];

/// E-state index tables (M0-M7)
const M0: [usize; 32] = [
    0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1,
    0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1,
];
const M1: [usize; 32] = [
    1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2,
    1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2,
];
const M2: [usize; 32] = [
    2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3,
    2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3,
];
const M3: [usize; 32] = [
    3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4,
    3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4,
];
const M4: [usize; 32] = [
    4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5,
    4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5,
];
const M5: [usize; 32] = [
    5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6,
    5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6,
];
const M6: [usize; 32] = [
    6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7,
    6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7,
];
const M7: [usize; 32] = [
    7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0,
    7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0,
];

/// Rotate right
#[inline]
fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

/// F1 boolean function
#[inline]
fn f1(x6: u32, x5: u32, x4: u32, x3: u32, x2: u32, x1: u32, x0: u32) -> u32 {
    (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x1) ^ x0
}

/// F2 boolean function
#[inline]
fn f2(x6: u32, x5: u32, x4: u32, x3: u32, x2: u32, x1: u32, x0: u32) -> u32 {
    (x1 & x2 & x3) ^ (x2 & x4 & x5) ^ (x1 & x2) ^ (x1 & x4)
        ^ (x2 & x6) ^ (x3 & x5) ^ (x4 & x5) ^ (x0 & x2) ^ x0
}

/// F3 boolean function
#[inline]
fn f3(x6: u32, x5: u32, x4: u32, x3: u32, x2: u32, x1: u32, x0: u32) -> u32 {
    (x1 & x2 & x3) ^ (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x3) ^ x0
}

/// F4 boolean function
#[inline]
fn f4(x6: u32, x5: u32, x4: u32, x3: u32, x2: u32, x1: u32, x0: u32) -> u32 {
    (x1 & x2 & x3) ^ (x2 & x4 & x5) ^ (x3 & x4 & x6)
        ^ (x1 & x4) ^ (x2 & x6) ^ (x3 & x4) ^ (x3 & x5)
        ^ (x3 & x6) ^ (x4 & x5) ^ (x4 & x6) ^ (x0 & x4) ^ x0
}

/// F5 boolean function
#[inline]
fn f5(x6: u32, x5: u32, x4: u32, x3: u32, x2: u32, x1: u32, x0: u32) -> u32 {
    (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x1 & x2 & x3) ^ (x0 & x5) ^ x0
}

/// Transform for 3-pass HAVAL
fn transform3(state: &mut [u32; 8], block: &[u8; 128]) {
    let mut e = *state;
    let mut x = [0u32; 32];

    // Decode block to 32-bit words (little-endian)
    for i in 0..32 {
        x[i] = u32::from_le_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    // Pass 1 (F1)
    for i in 0..32 {
        let f = f1(e[M1[i]], e[M0[i]], e[M3[i]], e[M5[i]], e[M6[i]], e[M2[i]], e[M4[i]]);
        e[7 - (i % 8)] = rotr(f, 7)
            .wrapping_add(rotr(e[M7[i]], 11))
            .wrapping_add(x[i]);
    }

    // Pass 2 (F2)
    for i in 0..32 {
        let f = f2(e[M4[i]], e[M2[i]], e[M1[i]], e[M0[i]], e[M5[i]], e[M3[i]], e[M6[i]]);
        e[7 - (i % 8)] = rotr(f, 7)
            .wrapping_add(rotr(e[M7[i]], 11))
            .wrapping_add(x[I2[i]])
            .wrapping_add(K2[i]);
    }

    // Pass 3 (F3)
    for i in 0..32 {
        let f = f3(e[M6[i]], e[M1[i]], e[M2[i]], e[M3[i]], e[M4[i]], e[M5[i]], e[M0[i]]);
        e[7 - (i % 8)] = rotr(f, 7)
            .wrapping_add(rotr(e[M7[i]], 11))
            .wrapping_add(x[I3[i]])
            .wrapping_add(K3[i]);
    }

    // Add to state
    for i in 0..8 {
        state[i] = state[i].wrapping_add(e[i]);
    }
}

/// Transform for 4-pass HAVAL
fn transform4(state: &mut [u32; 8], block: &[u8; 128]) {
    let mut e = *state;
    let mut x = [0u32; 32];

    for i in 0..32 {
        x[i] = u32::from_le_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    // Pass 1 (F1) - different E ordering for 4-pass
    for i in 0..32 {
        let f = f1(e[M2[i]], e[M6[i]], e[M1[i]], e[M4[i]], e[M5[i]], e[M3[i]], e[M0[i]]);
        e[7 - (i % 8)] = rotr(f, 7)
            .wrapping_add(rotr(e[M7[i]], 11))
            .wrapping_add(x[i]);
    }

    // Pass 2 (F2)
    for i in 0..32 {
        let f = f2(e[M3[i]], e[M5[i]], e[M2[i]], e[M0[i]], e[M1[i]], e[M6[i]], e[M4[i]]);
        e[7 - (i % 8)] = rotr(f, 7)
            .wrapping_add(rotr(e[M7[i]], 11))
            .wrapping_add(x[I2[i]])
            .wrapping_add(K2[i]);
    }

    // Pass 3 (F3)
    for i in 0..32 {
        let f = f3(e[M1[i]], e[M4[i]], e[M3[i]], e[M6[i]], e[M0[i]], e[M2[i]], e[M5[i]]);
        e[7 - (i % 8)] = rotr(f, 7)
            .wrapping_add(rotr(e[M7[i]], 11))
            .wrapping_add(x[I3[i]])
            .wrapping_add(K3[i]);
    }

    // Pass 4 (F4)
    for i in 0..32 {
        let f = f4(e[M6[i]], e[M4[i]], e[M0[i]], e[M5[i]], e[M2[i]], e[M1[i]], e[M3[i]]);
        e[7 - (i % 8)] = rotr(f, 7)
            .wrapping_add(rotr(e[M7[i]], 11))
            .wrapping_add(x[I4[i]])
            .wrapping_add(K4[i]);
    }

    for i in 0..8 {
        state[i] = state[i].wrapping_add(e[i]);
    }
}

/// Transform for 5-pass HAVAL
fn transform5(state: &mut [u32; 8], block: &[u8; 128]) {
    let mut e = *state;
    let mut x = [0u32; 32];

    for i in 0..32 {
        x[i] = u32::from_le_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    // Pass 1 (F1) - different E ordering for 5-pass
    for i in 0..32 {
        let f = f1(e[M3[i]], e[M4[i]], e[M1[i]], e[M0[i]], e[M5[i]], e[M2[i]], e[M6[i]]);
        e[7 - (i % 8)] = rotr(f, 7)
            .wrapping_add(rotr(e[M7[i]], 11))
            .wrapping_add(x[i]);
    }

    // Pass 2 (F2)
    for i in 0..32 {
        let f = f2(e[M6[i]], e[M2[i]], e[M1[i]], e[M0[i]], e[M3[i]], e[M4[i]], e[M5[i]]);
        e[7 - (i % 8)] = rotr(f, 7)
            .wrapping_add(rotr(e[M7[i]], 11))
            .wrapping_add(x[I2[i]])
            .wrapping_add(K2[i]);
    }

    // Pass 3 (F3)
    for i in 0..32 {
        let f = f3(e[M2[i]], e[M6[i]], e[M0[i]], e[M4[i]], e[M3[i]], e[M1[i]], e[M5[i]]);
        e[7 - (i % 8)] = rotr(f, 7)
            .wrapping_add(rotr(e[M7[i]], 11))
            .wrapping_add(x[I3[i]])
            .wrapping_add(K3[i]);
    }

    // Pass 4 (F4)
    for i in 0..32 {
        let f = f4(e[M1[i]], e[M5[i]], e[M3[i]], e[M2[i]], e[M0[i]], e[M4[i]], e[M6[i]]);
        e[7 - (i % 8)] = rotr(f, 7)
            .wrapping_add(rotr(e[M7[i]], 11))
            .wrapping_add(x[I4[i]])
            .wrapping_add(K4[i]);
    }

    // Pass 5 (F5)
    for i in 0..32 {
        let f = f5(e[M2[i]], e[M5[i]], e[M0[i]], e[M6[i]], e[M4[i]], e[M3[i]], e[M1[i]]);
        e[7 - (i % 8)] = rotr(f, 7)
            .wrapping_add(rotr(e[M7[i]], 11))
            .wrapping_add(x[I5[i]])
            .wrapping_add(K5[i]);
    }

    for i in 0..8 {
        state[i] = state[i].wrapping_add(e[i]);
    }
}

/// HAVAL context
struct HavalContext {
    state: [u32; 8],
    count: [u32; 2], // bit count
    buffer: [u8; 128],
    passes: u8,
    output_bits: u16,
}

impl HavalContext {
    fn new(passes: u8, output_bits: u16) -> Self {
        Self {
            state: D0,
            count: [0, 0],
            buffer: [0; 128],
            passes,
            output_bits,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let index = ((self.count[0] >> 3) & 0x7F) as usize;

        // Update bit count
        let bit_len = (data.len() as u32) << 3;
        self.count[0] = self.count[0].wrapping_add(bit_len);
        if self.count[0] < bit_len {
            self.count[1] = self.count[1].wrapping_add(1);
        }
        self.count[1] = self.count[1].wrapping_add((data.len() >> 29) as u32);

        let part_len = 128 - index;

        if data.len() >= part_len {
            self.buffer[index..index + part_len].copy_from_slice(&data[..part_len]);
            self.transform(&self.buffer.clone());
            let mut offset = part_len;

            while offset + 127 < data.len() {
                let block: [u8; 128] = data[offset..offset + 128].try_into().unwrap();
                self.transform(&block);
                offset += 128;
            }

            self.buffer[..data.len() - offset].copy_from_slice(&data[offset..]);
        } else {
            self.buffer[index..index + data.len()].copy_from_slice(data);
        }
    }

    fn transform(&mut self, block: &[u8; 128]) {
        match self.passes {
            3 => transform3(&mut self.state, block),
            4 => transform4(&mut self.state, block),
            5 => transform5(&mut self.state, block),
            _ => unreachable!(),
        }
    }

    fn finalize(mut self) -> Vec<u8> {
        // Build the 10-byte trailer
        let mut bits = [0u8; 10];

        // Version (3 bits) | Passes (3 bits) | Output bits low 2 bits
        bits[0] = (1 & 0x07) // HAVAL version = 1
            | ((self.passes & 0x07) << 3)
            | (((self.output_bits & 0x03) as u8) << 6);
        bits[1] = (self.output_bits >> 2) as u8;

        // Bit count (little-endian)
        bits[2..6].copy_from_slice(&self.count[0].to_le_bytes());
        bits[6..10].copy_from_slice(&self.count[1].to_le_bytes());

        // Pad to 118 mod 128
        let index = ((self.count[0] >> 3) & 0x7f) as usize;
        let pad_len = if index < 118 { 118 - index } else { 246 - index };

        // Padding starts with 0x01
        let mut padding = vec![0u8; pad_len];
        padding[0] = 0x01;
        self.update(&padding);

        // Append trailer
        self.update(&bits);

        // Fold state for smaller outputs
        self.fold_state();

        // Encode output
        let out_bytes = (self.output_bits / 8) as usize;
        let mut result = vec![0u8; out_bytes];
        for i in 0..(out_bytes / 4) {
            result[i * 4..(i + 1) * 4].copy_from_slice(&self.state[i].to_le_bytes());
        }
        result
    }

    fn fold_state(&mut self) {
        match self.output_bits {
            128 => {
                self.state[3] = self.state[3].wrapping_add(
                    (self.state[7] & 0xFF000000)
                        | (self.state[6] & 0x00FF0000)
                        | (self.state[5] & 0x0000FF00)
                        | (self.state[4] & 0x000000FF),
                );
                self.state[2] = self.state[2].wrapping_add(
                    (((self.state[7] & 0x00FF0000)
                        | (self.state[6] & 0x0000FF00)
                        | (self.state[5] & 0x000000FF))
                        << 8)
                        | ((self.state[4] & 0xFF000000) >> 24),
                );
                self.state[1] = self.state[1].wrapping_add(
                    (((self.state[7] & 0x0000FF00) | (self.state[6] & 0x000000FF)) << 16)
                        | (((self.state[5] & 0xFF000000) | (self.state[4] & 0x00FF0000)) >> 16),
                );
                self.state[0] = self.state[0].wrapping_add(
                    ((self.state[7] & 0x000000FF) << 24)
                        | (((self.state[6] & 0xFF000000)
                            | (self.state[5] & 0x00FF0000)
                            | (self.state[4] & 0x0000FF00))
                            >> 8),
                );
            }
            160 => {
                self.state[4] = self.state[4].wrapping_add(
                    ((self.state[7] & 0xFE000000)
                        | (self.state[6] & 0x01F80000)
                        | (self.state[5] & 0x0007F000))
                        >> 12,
                );
                self.state[3] = self.state[3].wrapping_add(
                    ((self.state[7] & 0x01F80000)
                        | (self.state[6] & 0x0007F000)
                        | (self.state[5] & 0x00000FC0))
                        >> 6,
                );
                self.state[2] = self.state[2].wrapping_add(
                    (self.state[7] & 0x0007F000)
                        | (self.state[6] & 0x00000FC0)
                        | (self.state[5] & 0x0000003F),
                );
                self.state[1] = self.state[1].wrapping_add(rotr(
                    (self.state[7] & 0x00000FC0)
                        | (self.state[6] & 0x0000003F)
                        | (self.state[5] & 0xFE000000),
                    25,
                ));
                self.state[0] = self.state[0].wrapping_add(rotr(
                    (self.state[7] & 0x0000003F)
                        | (self.state[6] & 0xFE000000)
                        | (self.state[5] & 0x01F80000),
                    19,
                ));
            }
            192 => {
                self.state[5] = self.state[5]
                    .wrapping_add(((self.state[7] & 0xFC000000) | (self.state[6] & 0x03E00000)) >> 21);
                self.state[4] = self.state[4]
                    .wrapping_add(((self.state[7] & 0x03E00000) | (self.state[6] & 0x001F0000)) >> 16);
                self.state[3] = self.state[3]
                    .wrapping_add(((self.state[7] & 0x001F0000) | (self.state[6] & 0x0000FC00)) >> 10);
                self.state[2] = self.state[2]
                    .wrapping_add(((self.state[7] & 0x0000FC00) | (self.state[6] & 0x000003E0)) >> 5);
                self.state[1] = self.state[1]
                    .wrapping_add((self.state[7] & 0x000003E0) | (self.state[6] & 0x0000001F));
                self.state[0] = self.state[0]
                    .wrapping_add(rotr((self.state[7] & 0x0000001F) | (self.state[6] & 0xFC000000), 26));
            }
            224 => {
                self.state[6] = self.state[6].wrapping_add(self.state[7] & 0x0000000F);
                self.state[5] = self.state[5].wrapping_add((self.state[7] >> 4) & 0x0000001F);
                self.state[4] = self.state[4].wrapping_add((self.state[7] >> 9) & 0x0000000F);
                self.state[3] = self.state[3].wrapping_add((self.state[7] >> 13) & 0x0000001F);
                self.state[2] = self.state[2].wrapping_add((self.state[7] >> 18) & 0x0000000F);
                self.state[1] = self.state[1].wrapping_add((self.state[7] >> 22) & 0x0000001F);
                self.state[0] = self.state[0].wrapping_add((self.state[7] >> 27) & 0x0000001F);
            }
            256 => {
                // No folding needed for 256-bit output
            }
            _ => unreachable!(),
        }
    }
}

// Public API functions for all 15 variants

/// HAVAL-128 with 3 passes
pub fn haval128_3(data: &[u8]) -> [u8; 16] {
    let mut ctx = HavalContext::new(3, 128);
    ctx.update(data);
    ctx.finalize().try_into().unwrap()
}

/// HAVAL-128 with 4 passes
pub fn haval128_4(data: &[u8]) -> [u8; 16] {
    let mut ctx = HavalContext::new(4, 128);
    ctx.update(data);
    ctx.finalize().try_into().unwrap()
}

/// HAVAL-128 with 5 passes
pub fn haval128_5(data: &[u8]) -> [u8; 16] {
    let mut ctx = HavalContext::new(5, 128);
    ctx.update(data);
    ctx.finalize().try_into().unwrap()
}

/// HAVAL-160 with 3 passes
pub fn haval160_3(data: &[u8]) -> [u8; 20] {
    let mut ctx = HavalContext::new(3, 160);
    ctx.update(data);
    ctx.finalize().try_into().unwrap()
}

/// HAVAL-160 with 4 passes
pub fn haval160_4(data: &[u8]) -> [u8; 20] {
    let mut ctx = HavalContext::new(4, 160);
    ctx.update(data);
    ctx.finalize().try_into().unwrap()
}

/// HAVAL-160 with 5 passes
pub fn haval160_5(data: &[u8]) -> [u8; 20] {
    let mut ctx = HavalContext::new(5, 160);
    ctx.update(data);
    ctx.finalize().try_into().unwrap()
}

/// HAVAL-192 with 3 passes
pub fn haval192_3(data: &[u8]) -> [u8; 24] {
    let mut ctx = HavalContext::new(3, 192);
    ctx.update(data);
    ctx.finalize().try_into().unwrap()
}

/// HAVAL-192 with 4 passes
pub fn haval192_4(data: &[u8]) -> [u8; 24] {
    let mut ctx = HavalContext::new(4, 192);
    ctx.update(data);
    ctx.finalize().try_into().unwrap()
}

/// HAVAL-192 with 5 passes
pub fn haval192_5(data: &[u8]) -> [u8; 24] {
    let mut ctx = HavalContext::new(5, 192);
    ctx.update(data);
    ctx.finalize().try_into().unwrap()
}

/// HAVAL-224 with 3 passes
pub fn haval224_3(data: &[u8]) -> [u8; 28] {
    let mut ctx = HavalContext::new(3, 224);
    ctx.update(data);
    ctx.finalize().try_into().unwrap()
}

/// HAVAL-224 with 4 passes
pub fn haval224_4(data: &[u8]) -> [u8; 28] {
    let mut ctx = HavalContext::new(4, 224);
    ctx.update(data);
    ctx.finalize().try_into().unwrap()
}

/// HAVAL-224 with 5 passes
pub fn haval224_5(data: &[u8]) -> [u8; 28] {
    let mut ctx = HavalContext::new(5, 224);
    ctx.update(data);
    ctx.finalize().try_into().unwrap()
}

/// HAVAL-256 with 3 passes
pub fn haval256_3(data: &[u8]) -> [u8; 32] {
    let mut ctx = HavalContext::new(3, 256);
    ctx.update(data);
    ctx.finalize().try_into().unwrap()
}

/// HAVAL-256 with 4 passes
pub fn haval256_4(data: &[u8]) -> [u8; 32] {
    let mut ctx = HavalContext::new(4, 256);
    ctx.update(data);
    ctx.finalize().try_into().unwrap()
}

/// HAVAL-256 with 5 passes
pub fn haval256_5(data: &[u8]) -> [u8; 32] {
    let mut ctx = HavalContext::new(5, 256);
    ctx.update(data);
    ctx.finalize().try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors verified against PHP 8.x using:
    // php -r 'echo hash("havalXXX,Y", "...");'

    // === HAVAL-128 tests ===
    #[test]
    fn test_haval128_3_empty() {
        let result = haval128_3(b"");
        let expected = hex::decode("c68f39913f901f3ddf44c707357a7d70").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval128_3_test() {
        let result = haval128_3(b"test");
        let expected = hex::decode("a26075021e24a5bda74794d85e9fdb7f").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval128_4_test() {
        let result = haval128_4(b"test");
        let expected = hex::decode("1ba3b2186ad54d024603d61ddb9d2f42").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval128_5_test() {
        let result = haval128_5(b"test");
        let expected = hex::decode("f5b480f6965efd5f5e6232925c5eed14").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    // === HAVAL-160 tests ===
    #[test]
    fn test_haval160_3_empty() {
        let result = haval160_3(b"");
        let expected = hex::decode("d353c3ae22a25401d257643836d7231a9a95f953").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval160_3_test() {
        let result = haval160_3(b"test");
        let expected = hex::decode("858c2c8f76afa7dd067d3d94c667c8aec6ac2650").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval160_4_test() {
        let result = haval160_4(b"test");
        let expected = hex::decode("516d3243a12ce3af38a005003c7221bf85299714").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval160_5_test() {
        let result = haval160_5(b"test");
        let expected = hex::decode("f5e3770031ebc6c46fe78d92890e17b1bef93b87").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    // === HAVAL-192 tests ===
    #[test]
    fn test_haval192_3_empty() {
        let result = haval192_3(b"");
        let expected = hex::decode("e9c48d7903eaf2a91c5b350151efcb175c0fc82de2289a4e").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval192_3_test() {
        let result = haval192_3(b"test");
        let expected = hex::decode("c4b8741917dabc27e2bebf58a6663a05b0d3dc43072a64b4").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval192_4_test() {
        let result = haval192_4(b"test");
        let expected = hex::decode("16ff6de6751cb654c1f788ee2f14ceddb86eec343ef87cd5").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval192_5_test() {
        let result = haval192_5(b"test");
        let expected = hex::decode("527383196142f6f3352f8a152dd06c9c0a50efcb83a646f0").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    // === HAVAL-224 tests ===
    #[test]
    fn test_haval224_3_empty() {
        let result = haval224_3(b"");
        let expected = hex::decode("c5aae9d47bffcaaf84a8c6e7ccacd60a0dd1932be7b1a192b9214b6d").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval224_3_test() {
        let result = haval224_3(b"test");
        let expected = hex::decode("f5b30a47580d8bfa256d6ed7604ffd2bb787abb22b53ad9f693e8d31").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval224_4_test() {
        let result = haval224_4(b"test");
        let expected = hex::decode("deea192a84b5e29ab958202b22a0b604c1df1298ee7d32ee5d7e2954").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval224_5_test() {
        let result = haval224_5(b"test");
        let expected = hex::decode("9666797abc57d096c2a9922e350390437f9c2e378ce2e43e0d816d90").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    // === HAVAL-256 tests ===
    #[test]
    fn test_haval256_3_empty() {
        let result = haval256_3(b"");
        let expected = hex::decode("4f6938531f0bc8991f62da7bbd6f7de3fad44562b8c6f4ebf146d5b4e46f7c17").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_3_test() {
        let result = haval256_3(b"test");
        let expected = hex::decode("593c9aed973bb51a3c852fb4e051d7c26686b9468b4e405350cb6805dc1b99e6").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_4_empty() {
        let result = haval256_4(b"");
        let expected = hex::decode("c92b2e23091e80e375dadce26982482d197b1a2521be82da819f8ca2c579b99b").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_4_test() {
        let result = haval256_4(b"test");
        let expected = hex::decode("435ded7266cba07f389d6e74c954b184e1ddacc8a7b8dc022db3ca4450a738cd").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_5_empty() {
        let result = haval256_5(b"");
        let expected = hex::decode("be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_5_test() {
        let result = haval256_5(b"test");
        let expected = hex::decode("a4b59d68e0111000856baca9e6573a2adc2b56b6b4d87f7cf31de24a77b93768").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    // === Multi-block tests ===
    #[test]
    fn test_haval256_3_1000_bytes() {
        let data = vec![b'a'; 1000];
        let result = haval256_3(&data);
        let expected = hex::decode("283a1cd61df7df0890b57228064ea8539955fcbffc4c8b7697ce8ce7b641c8af").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_3_fox() {
        let result = haval256_3(b"The quick brown fox jumps over the lazy dog");
        let expected = hex::decode("9446028f42b3768a41bd873ca69b0c006341d986613567f39eb61f96ca683300").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    // Multi-block with 4-pass
    #[test]
    fn test_haval256_4_1000_bytes() {
        let data = vec![b'a'; 1000];
        let result = haval256_4(&data);
        // Verified with PHP: hash("haval256,4", str_repeat("a", 1000))
        let expected = hex::decode("8a4ae896c0f2bcdb5d22eab2d3840652c831dabc1280290a62555966a2c178a4").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    // Multi-block with 5-pass
    #[test]
    fn test_haval256_5_1000_bytes() {
        let data = vec![b'a'; 1000];
        let result = haval256_5(&data);
        // Verified with PHP: hash("haval256,5", str_repeat("a", 1000))
        let expected = hex::decode("895160426130860e829459269691913009542a6ac51752f154847a9359618f44").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    // === Block boundary tests (block = 128 bytes) ===
    // Tests all 3 pass counts at the exact block boundary.

    #[test]
    fn test_haval256_3_127_bytes() {
        let result = haval256_3(&vec![b'a'; 127]);
        let expected = hex::decode("14b6e3418a669865cd25c413c8fbdf680e3420b563a468845271674405f52abd").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_3_128_bytes() {
        let result = haval256_3(&vec![b'a'; 128]);
        let expected = hex::decode("13faa4d94db48282d58e05b69be23ec24d1bf5c724dfdd7f2a1c17763f3d355f").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_3_129_bytes() {
        let result = haval256_3(&vec![b'a'; 129]);
        let expected = hex::decode("18229631aea1373425523a5e9a11aa8545c98376ebd07525f5f33aaed88bce50").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_4_127_bytes() {
        let result = haval256_4(&vec![b'a'; 127]);
        let expected = hex::decode("6380e8e8e2f3907f314fcddb51f48e3a55b0130a6bba01eec3c2b90e195e554e").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_4_128_bytes() {
        let result = haval256_4(&vec![b'a'; 128]);
        let expected = hex::decode("f30bc5d2ae4d446523b50f780111b79eb5caeceb0a4e6981638e539709776b99").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_4_129_bytes() {
        let result = haval256_4(&vec![b'a'; 129]);
        let expected = hex::decode("2acd67570c738a5a5f19eaaf2e9dd0202dfcd0e8e0129b742f1deda7a929eb0e").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_5_127_bytes() {
        let result = haval256_5(&vec![b'a'; 127]);
        let expected = hex::decode("f7eabeec467c8b56af40f90e799ea878d8ea7eff260d49982209364ad0e0c39d").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_5_128_bytes() {
        let result = haval256_5(&vec![b'a'; 128]);
        let expected = hex::decode("93390552a2d23df530a5918c95d095e3914cf476cd1d95bede099c7674b31efe").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_5_129_bytes() {
        let result = haval256_5(&vec![b'a'; 129]);
        let expected = hex::decode("a084bcc569ed32e30bb0c79e7b4f82be98c3934d2333ea7f6757c726382d6688").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    // === Padding boundary tests (HAVAL padding needs 10 bytes: version+passes+length) ===
    // At 118 mod 128, padding fits exactly. At 119+, padding spills to a new block.

    #[test]
    fn test_haval256_3_117_bytes() {
        let result = haval256_3(&vec![b'a'; 117]);
        let expected = hex::decode("3973ff8c2014d772f2999001c0a264543d1e1e8a968a5e32f81e37650583f639").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_3_118_bytes() {
        let result = haval256_3(&vec![b'a'; 118]);
        let expected = hex::decode("712f49ede266ce71c1421c5c90b898d20d96ee712b2c139fc7ff1830919f44f9").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_3_119_bytes() {
        let result = haval256_3(&vec![b'a'; 119]);
        let expected = hex::decode("0455661f2f02a015d9cf3c411af0509080124a7e628b84ec33e68432e88d7cd2").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_5_117_bytes() {
        let result = haval256_5(&vec![b'a'; 117]);
        let expected = hex::decode("5ccc1fcc4aca9ab3a014732dbafee7ed7c0cf1028b4bbaffe92a9d78e634ee02").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_5_118_bytes() {
        let result = haval256_5(&vec![b'a'; 118]);
        let expected = hex::decode("34e1b82fdea5bf0d5eec513d8bc463d2eeab36a2af5f5183cc98b564e51431b0").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_5_119_bytes() {
        let result = haval256_5(&vec![b'a'; 119]);
        let expected = hex::decode("e317fa1b993386e8e4c38f6a9a3bb4ae1f903d00df13d16a86f13fbb68a11a28").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    // === Signedness tests (0xFF bytes stress u32 arithmetic) ===
    // Tests one variant per pass count across different output sizes.

    #[test]
    fn test_haval128_3_32_0xff() {
        let result = haval128_3(&vec![0xFFu8; 32]);
        let expected = hex::decode("7a7d7b4fe180aaff15a796812058dc84").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval192_4_64_0xff() {
        let result = haval192_4(&vec![0xFFu8; 64]);
        let expected = hex::decode("6b9899802943e2ec9d48f2cf43edb48819e89592873f8815").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_5_128_0xff() {
        let result = haval256_5(&vec![0xFFu8; 128]);
        let expected = hex::decode("02eacd6a9862004632406b6724655b1d6dc98b4ce07b2c8bff129dcba98e170a").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval160_3_64_0xff() {
        let result = haval160_3(&vec![0xFFu8; 64]);
        let expected = hex::decode("feb47e0f6a2dae09bb68b3e6215af212bcce4ce5").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval224_5_64_0xff() {
        let result = haval224_5(&vec![0xFFu8; 64]);
        let expected = hex::decode("b641c9d8b48a577eda510b52031b3507085a2837b39fd4c32dc8c43d").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    // === Single byte edge cases ===

    #[test]
    fn test_haval256_3_single_0x00() {
        let result = haval256_3(&[0x00]);
        let expected = hex::decode("3a9ac785b9f8a38adf82cb7342a00ae29e259e5f4c40f567f9083c5af1000100").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_3_single_0x80() {
        let result = haval256_3(&[0x80]);
        let expected = hex::decode("5fc7d7c3067b4fab91e1b9c79875bdafe961d68d784224ad26d5fd1e9bf18ba4").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_3_single_0xff() {
        let result = haval256_3(&[0xFF]);
        let expected = hex::decode("f535a93dda842a6f96b6350d3fe8f31c6b9efbc2ffe20bd7ea92f34bd3e7da7d").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_5_single_0x80() {
        let result = haval256_5(&[0x80]);
        let expected = hex::decode("09a52378aee3d34064d6350d8e607a7f63fd48e86ab5f5b4a874d96cbac060c1").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    // === Alternating bit patterns ===

    #[test]
    fn test_haval256_3_alternating_0x55() {
        let result = haval256_3(&vec![0x55u8; 64]);
        let expected = hex::decode("169251ffd88646e661f5ce063a2c4d3e6602c62133b78ccdc0074a6a263c3c20").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_3_alternating_0xaa() {
        let result = haval256_3(&vec![0xAAu8; 64]);
        let expected = hex::decode("d7363eff6e7c5e7196fcfa3e75fd06f523703be949d77aa4cdc46949b517b341").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    // === Cross-variant consistency with binary input ===
    // Tests all output sizes with 3-pass using 0xFF input

    #[test]
    fn test_haval128_3_128_0xff() {
        let result = haval128_3(&vec![0xFFu8; 128]);
        let expected = hex::decode("5433edce884d9f1c27de62e4a33033ed").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval160_3_128_0xff() {
        let result = haval160_3(&vec![0xFFu8; 128]);
        let expected = hex::decode("b0c2a1fd450ccc7bd5cd12908c4c2ed2cdd1d9f5").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval192_3_128_0xff() {
        let result = haval192_3(&vec![0xFFu8; 128]);
        let expected = hex::decode("39e003261c4de2a9f40f4f79a557406f5b831e41825df99c").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval224_3_128_0xff() {
        let result = haval224_3(&vec![0xFFu8; 128]);
        let expected = hex::decode("886ceeadcebf60b70876186e7ebd29fc5e08572179f039e6119c8bfd").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_3_128_0xff() {
        let result = haval256_3(&vec![0xFFu8; 128]);
        let expected = hex::decode("412b93ac63c5cbcabb73c87b436d4e0cbf5554c513230411a75c063a5bf7e94e").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    // === Large input: 100003 bytes from SHA256(counter) ===
    // Input is SHA256(0_u64_le) || SHA256(1_u64_le) || ... truncated to 100003 bytes.
    // 100003 is prime, ensuring non-aligned multi-block processing.
    // Tests one variant per pass count.

    #[test]
    fn test_haval256_3_sha256_counter_100003() {
        use sha2::{Sha256, Digest};
        let mut data = Vec::with_capacity(100003);
        let mut counter: u64 = 0;
        while data.len() < 100003 {
            let mut hasher = Sha256::new();
            hasher.update(counter.to_le_bytes());
            data.extend_from_slice(&hasher.finalize());
            counter += 1;
        }
        data.truncate(100003);
        let result = haval256_3(&data);
        let expected = hex::decode("9c7b45688f2a00549dd06139d8dbaa7ae61c8b64dc7f04f33a29c10956a27e01").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_4_sha256_counter_100003() {
        use sha2::{Sha256, Digest};
        let mut data = Vec::with_capacity(100003);
        let mut counter: u64 = 0;
        while data.len() < 100003 {
            let mut hasher = Sha256::new();
            hasher.update(counter.to_le_bytes());
            data.extend_from_slice(&hasher.finalize());
            counter += 1;
        }
        data.truncate(100003);
        let result = haval256_4(&data);
        let expected = hex::decode("8abc17b3d52ec83762392d3766715be1583fb6e32022f1b9a6d20c08d3c7371b").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_haval256_5_sha256_counter_100003() {
        use sha2::{Sha256, Digest};
        let mut data = Vec::with_capacity(100003);
        let mut counter: u64 = 0;
        while data.len() < 100003 {
            let mut hasher = Sha256::new();
            hasher.update(counter.to_le_bytes());
            data.extend_from_slice(&hasher.finalize());
            counter += 1;
        }
        data.truncate(100003);
        let result = haval256_5(&data);
        let expected = hex::decode("bc091e4b3ec6700bb6ec1cb9f80869bd9344a9ba4c946f9a4eb2716c722b60a0").unwrap();
        assert_eq!(&result[..], &expected[..]);
    }
}
