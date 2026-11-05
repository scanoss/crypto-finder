use sha2::{Digest, Sha256};

// Bare #[get]: the crate root's #[macro_use] extern crate rocket brings it in.
#[get("/")]
pub fn index() -> String {
    format!("{:x}", Sha256::digest(b"rocket-macro-use"))
}

#[rocket::post("/store", data = "<body>")]
pub fn store(body: String) -> String {
    format!("{:x}", Sha256::digest(body.as_bytes()))
}

#[catch(404)]
pub fn not_found() -> String {
    format!("{:x}", Sha256::digest(b"rocket-catch"))
}

// No attribute, nothing calls it.
pub fn unmounted() -> String {
    format!("{:x}", Sha256::digest(b"rocket-unmounted"))
}
