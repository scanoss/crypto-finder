mod actix;
mod axum_app;
mod glob_actix;
mod glob_axum;
mod lambda_app;
mod lookalike;
mod poem_app;
mod tonic_app;
mod warp_app;

use sha2::{Digest, Sha256};

#[tokio::main]
async fn main() {
    let digest = Sha256::digest(b"tokio-main");
    println!("{:x}", digest);
}
