use axum::{routing::get, Router};
use sha2::{Digest, Sha256};

// A handler the entry-point catalog recognizes: its entry_kind is part of the
// structural graph.
async fn digest(body: String) -> String {
    format!("{:x}", Sha256::digest(body.as_bytes()))
}

pub fn router() -> Router {
    Router::new().route("/digest", get(digest))
}
