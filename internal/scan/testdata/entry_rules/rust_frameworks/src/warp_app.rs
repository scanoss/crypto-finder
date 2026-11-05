use sha2::{Digest, Sha256};
use warp::Filter;

async fn list_keys() -> Result<String, warp::Rejection> {
    Ok(format!("{:x}", Sha256::digest(b"warp-and-then")))
}

fn hello(name: String) -> String {
    format!("{}{:x}", name, Sha256::digest(b"warp-map"))
}

async fn recover_err(_err: warp::Rejection) -> Result<String, std::convert::Infallible> {
    Ok(format!("{:x}", Sha256::digest(b"warp-recover")))
}

pub fn routes() -> impl Filter<Extract = (String,), Error = std::convert::Infallible> + Clone {
    let keys = warp::path("keys").and(warp::get());
    let list = keys.and_then(list_keys);
    let hi = warp::path!("hello" / String).map(hello);
    list.or(hi).unify().recover(recover_err).unify()
}
