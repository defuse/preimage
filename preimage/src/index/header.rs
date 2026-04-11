use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{bail, Result};

use super::entry::ENTRY_SIZE;
use crate::get_algorithm;

pub(crate) const HEADER_MAGIC: &[u8; 16] = b"PREIMAGE-IDX\0\0\0\0";
pub(crate) const HEADER_VERSION_V1: u32 = 1;
pub(crate) const HEADER_SIZE_V1: usize = 256;
pub(crate) const HASH_NAME_LEN: usize = 128;
pub(crate) const RESERVED_LEN: usize = 88;
pub(crate) const SUPPORTED_HASH_PREFIX_BITS: u32 = 64;
pub(crate) const SUPPORTED_DICTIONARY_ADDRESS_BITS: u32 = 48;
const HASH_NAME_OFFSET: usize = 24;
const HASH_PREFIX_BITS_OFFSET: usize = 152;
const DICTIONARY_ADDRESS_BITS_OFFSET: usize = 156;
const ENTRY_COUNT_OFFSET: usize = 160;
const RESERVED_OFFSET: usize = 168;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IndexState {
    Creating = 1,
    Created = 2,
    Sorting = 3,
    Sorted = 4,
}

impl IndexState {
    fn from_u32(value: u32) -> Result<Self> {
        match value {
            1 => Ok(Self::Creating),
            2 => Ok(Self::Created),
            3 => Ok(Self::Sorting),
            4 => Ok(Self::Sorted),
            _ => bail!("unknown index state: {value}"),
        }
    }

    fn to_u32(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IndexHeaderV1 {
    pub(crate) state: IndexState,
    pub(crate) hash_name: String,
    pub(crate) hash_prefix_bits: u32,
    pub(crate) dictionary_address_bits: u32,
    pub(crate) entry_count: u64,
}

impl IndexHeaderV1 {
    pub(crate) fn new(state: IndexState, hash_name: &str, entry_count: u64) -> Self {
        Self {
            state,
            hash_name: hash_name.to_string(),
            hash_prefix_bits: SUPPORTED_HASH_PREFIX_BITS,
            dictionary_address_bits: SUPPORTED_DICTIONARY_ADDRESS_BITS,
            entry_count,
        }
    }

    pub(crate) fn entry_size_bytes(&self) -> usize {
        bits_to_bytes(self.hash_prefix_bits) + bits_to_bytes(self.dictionary_address_bits)
    }

    pub(crate) fn encode(&self) -> [u8; HEADER_SIZE_V1] {
        let mut bytes = [0u8; HEADER_SIZE_V1];
        bytes[..16].copy_from_slice(HEADER_MAGIC);
        bytes[16..20].copy_from_slice(&HEADER_VERSION_V1.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.state.to_u32().to_le_bytes());

        let hash_name = self.hash_name.as_bytes();
        assert!(
            hash_name.is_ascii(),
            "header hash name must be ASCII: {:?}",
            self.hash_name
        );
        assert!(
            hash_name.len() <= HASH_NAME_LEN,
            "header hash name too long: {} > {}",
            hash_name.len(),
            HASH_NAME_LEN
        );
        bytes[HASH_NAME_OFFSET..HASH_NAME_OFFSET + hash_name.len()].copy_from_slice(hash_name);

        bytes[HASH_PREFIX_BITS_OFFSET..HASH_PREFIX_BITS_OFFSET + 4]
            .copy_from_slice(&self.hash_prefix_bits.to_le_bytes());
        bytes[DICTIONARY_ADDRESS_BITS_OFFSET..DICTIONARY_ADDRESS_BITS_OFFSET + 4]
            .copy_from_slice(&self.dictionary_address_bits.to_le_bytes());
        bytes[ENTRY_COUNT_OFFSET..ENTRY_COUNT_OFFSET + 8]
            .copy_from_slice(&self.entry_count.to_le_bytes());
        bytes
    }

    pub(crate) fn decode(bytes: &[u8; HEADER_SIZE_V1]) -> Result<Self> {
        if &bytes[..16] != HEADER_MAGIC {
            bail!("invalid index header magic");
        }

        let header_version = u32::from_le_bytes(bytes[16..20].try_into().expect("slice length"));
        if header_version != HEADER_VERSION_V1 {
            bail!("unsupported index header version: {header_version}");
        }

        let state_raw = u32::from_le_bytes(bytes[20..24].try_into().expect("slice length"));
        let state = IndexState::from_u32(state_raw)?;

        let hash_name = decode_hash_name(
            bytes[HASH_NAME_OFFSET..HASH_NAME_OFFSET + HASH_NAME_LEN]
                .try_into()
                .expect("slice length"),
        )?;
        if get_algorithm(&hash_name).is_none() {
            bail!("unsupported hash algorithm in index header: {hash_name}");
        }

        let hash_prefix_bits = u32::from_le_bytes(
            bytes[HASH_PREFIX_BITS_OFFSET..HASH_PREFIX_BITS_OFFSET + 4]
                .try_into()
                .expect("slice length"),
        );
        if hash_prefix_bits != SUPPORTED_HASH_PREFIX_BITS {
            bail!("unsupported hash prefix width in index header: {hash_prefix_bits}");
        }

        let dictionary_address_bits = u32::from_le_bytes(
            bytes[DICTIONARY_ADDRESS_BITS_OFFSET..DICTIONARY_ADDRESS_BITS_OFFSET + 4]
                .try_into()
                .expect("slice length"),
        );
        if dictionary_address_bits != SUPPORTED_DICTIONARY_ADDRESS_BITS {
            bail!(
                "unsupported dictionary address width in index header: {dictionary_address_bits}"
            );
        }

        let entry_count = u64::from_le_bytes(
            bytes[ENTRY_COUNT_OFFSET..ENTRY_COUNT_OFFSET + 8]
                .try_into()
                .expect("slice length"),
        );

        let reserved = &bytes[RESERVED_OFFSET..RESERVED_OFFSET + RESERVED_LEN];
        if reserved.iter().any(|&b| b != 0) {
            bail!("nonzero reserved bytes in index header");
        }

        let header = Self {
            state,
            hash_name,
            hash_prefix_bits,
            dictionary_address_bits,
            entry_count,
        };

        if header.entry_size_bytes() != ENTRY_SIZE {
            bail!(
                "unsupported derived entry size in index header: {}",
                header.entry_size_bytes()
            );
        }

        Ok(header)
    }

    pub(crate) fn validate_algorithm_name(&self, supplied_algorithm_name: &str) -> Result<()> {
        if self.hash_name != supplied_algorithm_name {
            bail!(
                "index algorithm mismatch: header={}, requested={}",
                self.hash_name,
                supplied_algorithm_name
            );
        }
        Ok(())
    }

    pub(crate) fn require_lookup_ready(&self) -> Result<()> {
        match self.state {
            IndexState::Sorted => Ok(()),
            IndexState::Creating => bail!("index build did not finish cleanly"),
            IndexState::Created => bail!("index is not sorted"),
            IndexState::Sorting => bail!("index sort did not finish cleanly"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum IndexFormatMetadata {
    Legacy {
        data_offset: u64,
        entry_size: usize,
        entry_count: u64,
    },
    HeaderV1 {
        data_offset: u64,
        entry_size: usize,
        entry_count: u64,
        header: IndexHeaderV1,
    },
}

impl IndexFormatMetadata {
    pub(crate) fn data_offset(&self) -> u64 {
        match self {
            Self::Legacy { data_offset, .. } => *data_offset,
            Self::HeaderV1 { data_offset, .. } => *data_offset,
        }
    }

    pub(crate) fn entry_size(&self) -> usize {
        match self {
            Self::Legacy { entry_size, .. } => *entry_size,
            Self::HeaderV1 { entry_size, .. } => *entry_size,
        }
    }

    pub(crate) fn entry_count(&self) -> u64 {
        match self {
            Self::Legacy { entry_count, .. } => *entry_count,
            Self::HeaderV1 { entry_count, .. } => *entry_count,
        }
    }

    pub(crate) fn header(&self) -> Option<&IndexHeaderV1> {
        match self {
            Self::Legacy { .. } => None,
            Self::HeaderV1 { header, .. } => Some(header),
        }
    }
}

pub(crate) fn read_index_metadata(index_path: &Path) -> Result<IndexFormatMetadata> {
    let mut file = File::open(index_path)?;
    let file_size = file.metadata()?.len();

    if file_size >= HEADER_MAGIC.len() as u64 {
        let mut magic = [0u8; 16];
        file.read_exact(&mut magic)?;
        if &magic == HEADER_MAGIC {
            if file_size < HEADER_SIZE_V1 as u64 {
                bail!(
                    "index file is truncated inside header: {} < {}",
                    file_size,
                    HEADER_SIZE_V1
                );
            }

            let mut header_bytes = [0u8; HEADER_SIZE_V1];
            header_bytes[..16].copy_from_slice(HEADER_MAGIC);
            file.read_exact(&mut header_bytes[16..])?;
            let header = IndexHeaderV1::decode(&header_bytes)?;
            let payload_size = file_size - HEADER_SIZE_V1 as u64;
            let entry_size = header.entry_size_bytes();
            let expected_payload_size = header
                .entry_count
                .checked_mul(entry_size as u64)
                .expect("header entry count multiplication must not overflow");
            if payload_size != expected_payload_size {
                bail!(
                    "index payload size does not match header entry count: payload={}, expected={}",
                    payload_size,
                    expected_payload_size
                );
            }

            return Ok(IndexFormatMetadata::HeaderV1 {
                data_offset: HEADER_SIZE_V1 as u64,
                entry_size,
                entry_count: header.entry_count,
                header,
            });
        }
    }

    if file_size % ENTRY_SIZE as u64 != 0 {
        bail!(
            "index file size {} is not a multiple of entry size {}",
            file_size,
            ENTRY_SIZE
        );
    }

    Ok(IndexFormatMetadata::Legacy {
        data_offset: 0,
        entry_size: ENTRY_SIZE,
        entry_count: file_size / ENTRY_SIZE as u64,
    })
}

pub(crate) fn write_header(writer: &mut (impl Write + Seek), header: &IndexHeaderV1) -> Result<()> {
    writer.seek(SeekFrom::Start(0))?;
    writer.write_all(&header.encode())?;
    writer.flush()?;
    Ok(())
}

fn bits_to_bytes(bits: u32) -> usize {
    bits.div_ceil(8) as usize
}

fn decode_hash_name(bytes: &[u8; HASH_NAME_LEN]) -> Result<String> {
    let nul_pos = bytes.iter().position(|&b| b == 0).unwrap_or(HASH_NAME_LEN);
    if bytes[nul_pos..].iter().any(|&b| b != 0) {
        bail!("index header hash name is not NUL-padded ASCII");
    }

    let hash_name_bytes = &bytes[..nul_pos];
    if hash_name_bytes.is_empty() {
        bail!("index header hash name is empty");
    }
    if !hash_name_bytes.is_ascii() {
        bail!("index header hash name is not ASCII");
    }

    Ok(std::str::from_utf8(hash_name_bytes)
        .expect("ASCII is valid UTF-8")
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_header_roundtrip() {
        let header = IndexHeaderV1::new(IndexState::Created, "md5", 123);
        let encoded = header.encode();
        let decoded = IndexHeaderV1::decode(&encoded).expect("decode");

        assert_eq!(decoded.state, IndexState::Created);
        assert_eq!(decoded.hash_name, "md5");
        assert_eq!(decoded.hash_prefix_bits, 64);
        assert_eq!(decoded.dictionary_address_bits, 48);
        assert_eq!(decoded.entry_count, 123);
        assert_eq!(decoded.entry_size_bytes(), ENTRY_SIZE);
    }

    #[test]
    fn test_decode_rejects_unknown_version() {
        let header = IndexHeaderV1::new(IndexState::Created, "md5", 0);
        let mut encoded = header.encode();
        encoded[16..20].copy_from_slice(&2u32.to_le_bytes());

        let err = IndexHeaderV1::decode(&encoded).expect_err("should reject");
        assert_eq!(err.to_string(), "unsupported index header version: 2");
    }

    #[test]
    fn test_decode_rejects_nonzero_reserved() {
        let header = IndexHeaderV1::new(IndexState::Created, "md5", 0);
        let mut encoded = header.encode();
        encoded[200] = 1;

        let err = IndexHeaderV1::decode(&encoded).expect_err("should reject");
        assert_eq!(err.to_string(), "nonzero reserved bytes in index header");
    }

    #[test]
    fn test_decode_rejects_non_ascii_hash_name() {
        let header = IndexHeaderV1::new(IndexState::Created, "md5", 0);
        let mut encoded = header.encode();
        encoded[24] = 0xFF;
        encoded[25] = 0;
        for byte in &mut encoded[26..152] {
            *byte = 0;
        }

        let err = IndexHeaderV1::decode(&encoded).expect_err("should reject");
        assert_eq!(err.to_string(), "index header hash name is not ASCII");
    }

    #[test]
    fn test_decode_rejects_unsupported_hash_name() {
        let header = IndexHeaderV1::new(IndexState::Created, "md5", 0);
        let mut encoded = header.encode();
        let name = b"not-a-real-hash";
        encoded[24..24 + name.len()].copy_from_slice(name);
        encoded[24 + name.len()] = 0;
        for byte in &mut encoded[24 + name.len() + 1..152] {
            *byte = 0;
        }

        let err = IndexHeaderV1::decode(&encoded).expect_err("should reject");
        assert_eq!(
            err.to_string(),
            "unsupported hash algorithm in index header: not-a-real-hash"
        );
    }

    #[test]
    fn test_read_index_metadata_detects_legacy_index() {
        let mut file = NamedTempFile::new().expect("temp file");
        file.write_all(&[0u8; ENTRY_SIZE * 2]).expect("write");
        file.flush().expect("flush");

        let metadata = read_index_metadata(file.path()).expect("read metadata");
        assert_eq!(
            metadata,
            IndexFormatMetadata::Legacy {
                data_offset: 0,
                entry_size: ENTRY_SIZE,
                entry_count: 2,
            }
        );
    }

    #[test]
    fn test_read_index_metadata_detects_headered_index() {
        let mut file = NamedTempFile::new().expect("temp file");
        let header = IndexHeaderV1::new(IndexState::Sorted, "md5", 3);
        file.write_all(&header.encode()).expect("write header");
        file.write_all(&[0u8; ENTRY_SIZE * 3]).expect("write payload");
        file.flush().expect("flush");

        let metadata = read_index_metadata(file.path()).expect("read metadata");
        assert_eq!(
            metadata,
            IndexFormatMetadata::HeaderV1 {
                data_offset: HEADER_SIZE_V1 as u64,
                entry_size: ENTRY_SIZE,
                entry_count: 3,
                header,
            }
        );
    }

    #[test]
    fn test_read_index_metadata_rejects_header_entry_count_mismatch() {
        let mut file = NamedTempFile::new().expect("temp file");
        let header = IndexHeaderV1::new(IndexState::Sorted, "md5", 3);
        file.write_all(&header.encode()).expect("write header");
        file.write_all(&[0u8; ENTRY_SIZE * 2]).expect("write payload");
        file.flush().expect("flush");

        let err = read_index_metadata(file.path()).expect_err("should reject");
        assert_eq!(
            err.to_string(),
            format!(
                "index payload size does not match header entry count: payload={}, expected={}",
                ENTRY_SIZE * 2,
                ENTRY_SIZE * 3
            )
        );
    }
}
