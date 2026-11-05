use sha2::{Digest, Sha256};

// Bare #[get] in a submodule of src/bin/worker.rs.
#[get("/run")]
pub fn run() -> String {
    format!("{:x}", Sha256::digest(b"bins-only-worker"))
}
