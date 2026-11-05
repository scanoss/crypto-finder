use sha2::{Digest, Sha256};

// Bare #[get] in a module of a multi-file binary: gateway/main.rs brings it in.
#[get("/health")]
pub fn health() -> String {
    format!("{:x}", Sha256::digest(b"bins-only-gateway"))
}
