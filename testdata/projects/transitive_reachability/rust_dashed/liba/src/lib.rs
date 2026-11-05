//! A direct dependency with no hashing of its own. Its package name holds a
//! dash, so callers write trans_liba.

/// The path the application calls.
pub fn used(data: &[u8]) -> Vec<u8> {
    libb_hashing::used_hash(data)
}

/// A path nothing in the application calls.
pub fn unused(data: &[u8]) -> Vec<u8> {
    libb_hashing::unused_hash(data)
}
