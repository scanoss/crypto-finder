use axum::routing;
use axum::{routing::get, Router};
use sha2::{Digest, Sha256};

async fn list() -> String {
    format!("{:x}", Sha256::digest(b"axum-get"))
}

async fn create() -> String {
    format!("{:x}", Sha256::digest(b"axum-chained-post"))
}

async fn remove() -> String {
    format!("{:x}", Sha256::digest(b"axum-routing-delete"))
}

async fn not_found() -> String {
    format!("{:x}", Sha256::digest(b"axum-fallback"))
}

mod handlers {
    use sha2::{Digest, Sha256};

    pub async fn health() -> String {
        format!("{:x}", Sha256::digest(b"axum-module-handler"))
    }
}

pub fn router() -> Router {
    let app = Router::new()
        .route("/items", get(list).post(create))
        .route("/items/{id}", routing::delete(remove))
        .route("/health", axum::routing::get(handlers::health));
    app.fallback(not_found)
}
