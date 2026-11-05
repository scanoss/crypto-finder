mod crypto;
mod handlers;

use axum::{routing::get, Router};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/digest", get(handlers::digest))
        .route("/sign", axum::routing::post(handlers::sign));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
