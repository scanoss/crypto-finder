//! A transitive dependency that does the hashing. Its package is trans-libb
//! and its [lib] name is libb_hashing, which is what callers write.

use transhash::{Sha256, Sha512};

/// Reached from the application through trans_liba::used.
pub fn used_hash(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data)
}

/// Reached only from trans_liba::unused.
pub fn unused_hash(data: &[u8]) -> Vec<u8> {
    Sha512::digest(data)
}
