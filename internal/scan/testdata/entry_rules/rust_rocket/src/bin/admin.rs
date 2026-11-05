#[macro_use]
extern crate rocket;

use sha2::{Digest, Sha256};

// Bare #[get] under this binary's own #[macro_use] extern crate rocket.
#[get("/admin")]
fn admin() -> String {
    format!("{:x}", Sha256::digest(b"rocket-bin-macro-use"))
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![admin])
}
