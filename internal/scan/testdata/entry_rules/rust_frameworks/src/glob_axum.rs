// Names a glob import brings in from axum::routing, and a glob of warp that
// must not claim a call on a futures value.
use axum::routing::*;
use axum::Router;
use futures::TryFutureExt;
use sha2::{Digest, Sha256};
use warp::*;

async fn glob_list() -> String {
    format!("{:x}", Sha256::digest(b"glob-axum-get"))
}

async fn glob_step(_v: u8) -> Result<String, ()> {
    Ok(format!("{:x}", Sha256::digest(b"glob-futures-and-then")))
}

pub fn router() -> Router {
    let _ = futures::future::ready(Ok::<u8, ()>(1)).and_then(glob_step);
    Router::new().route("/glob", get(glob_list))
}
