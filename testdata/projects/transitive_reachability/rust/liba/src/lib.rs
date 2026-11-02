//! A direct dependency with no hashing of its own.

/// The path the application calls.
pub fn used(data: &[u8]) -> Vec<u8> {
    translibb::used_hash(data)
}

/// A path nothing in the application calls.
pub fn unused(data: &[u8]) -> Vec<u8> {
    translibb::unused_hash(data)
}
