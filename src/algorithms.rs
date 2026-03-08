use crate::hashes::*;
use crate::HashAlgorithm;

/// Look up a built-in algorithm by its CLI name (case-sensitive).
pub fn get_algorithm(name: &str) -> Option<Box<dyn HashAlgorithm>> {
    match name {
        "md2" => Some(Box::new(Md2)),
        "md4" => Some(Box::new(Md4)),
        "md5" => Some(Box::new(Md5)),
        "sha1" => Some(Box::new(Sha1)),
        "sha224" => Some(Box::new(Sha224)),
        "sha256" => Some(Box::new(Sha256)),
        "sha384" => Some(Box::new(Sha384)),
        "sha512" => Some(Box::new(Sha512)),
        "whirlpool" => Some(Box::new(Whirlpool)),
        "ripemd160" => Some(Box::new(Ripemd160)),
        "NTLM" => Some(Box::new(Ntlm)),
        "LM" => Some(Box::new(Lm)),
        "md5(md5)" => Some(Box::new(Md5Md5)),
        "MySQL4.1+" => Some(Box::new(MySql41)),
        "QubesV3.1BackupDefaults" => Some(Box::new(QubesV31)),
        _ => None,
    }
}

pub const ALGORITHM_NAMES: &[&str] = &[
    "md2", "md4", "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "whirlpool", "ripemd160", "LM", "NTLM", "md5(md5)", "MySQL4.1+",
    "QubesV3.1BackupDefaults",
];
