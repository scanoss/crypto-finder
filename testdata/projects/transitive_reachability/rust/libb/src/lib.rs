//! A transitive dependency that does the hashing.

use transhash::{Sha256, Sha512};

/// Reached from the application through transliba::used.
pub fn used_hash(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data)
}

/// Reached only from transliba::unused.
pub fn unused_hash(data: &[u8]) -> Vec<u8> {
    Sha512::digest(data)
}
