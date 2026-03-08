use crate::hashes::{
    HashAlgorithm,
    MD2, MD4, MD5, SHA1, SHA224, SHA256, SHA384, SHA512,
    WHIRLPOOL, RIPEMD160, LM, NTLM, MD5MD5, MYSQL41, QUBESV31,
};

/// Look up a built-in algorithm by its CLI name (case-sensitive).
///
/// Returns a static reference — no heap allocation.
pub fn get_algorithm(name: &str) -> Option<&'static dyn HashAlgorithm> {
    match name {
        "md2" => Some(MD2),
        "md4" => Some(MD4),
        "md5" => Some(MD5),
        "sha1" => Some(SHA1),
        "sha224" => Some(SHA224),
        "sha256" => Some(SHA256),
        "sha384" => Some(SHA384),
        "sha512" => Some(SHA512),
        "whirlpool" => Some(WHIRLPOOL),
        "ripemd160" => Some(RIPEMD160),
        "NTLM" => Some(NTLM),
        "LM" => Some(LM),
        "md5(md5)" => Some(MD5MD5),
        "MySQL4.1+" => Some(MYSQL41),
        "QubesV3.1BackupDefaults" => Some(QUBESV31),
        _ => None,
    }
}

pub const ALGORITHM_NAMES: &[&str] = &[
    "md2", "md4", "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "whirlpool", "ripemd160", "LM", "NTLM", "md5(md5)", "MySQL4.1+",
    "QubesV3.1BackupDefaults",
];
