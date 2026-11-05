use poem::{get, handler, Route};
use poem_openapi::{payload::PlainText, OpenApi};
use sha2::{Digest, Sha256};

#[handler]
fn hello() -> String {
    format!("{:x}", Sha256::digest(b"poem-handler"))
}

pub struct Api;

#[OpenApi]
impl Api {
    #[oai(path = "/hash", method = "get")]
    async fn hash(&self) -> PlainText<String> {
        PlainText(format!("{:x}", Sha256::digest(b"poem-openapi")))
    }
}

pub fn app() -> Route {
    Route::new().at("/hello", get(hello))
}
