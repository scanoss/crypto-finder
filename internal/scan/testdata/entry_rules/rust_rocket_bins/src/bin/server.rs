// A package with only binaries: no src/lib.rs, no src/main.rs.
#[macro_use]
extern crate rocket;

use sha2::{Digest, Sha256};

#[get("/")]
fn index() -> String {
    format!("{:x}", Sha256::digest(b"bins-only-server"))
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index])
}
