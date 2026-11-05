#[macro_use]
extern crate rocket;

mod routes;

use sha2::{Digest, Sha256};

#[launch]
fn rocket() -> _ {
    let _seed = Sha256::digest(b"rocket-launch");
    rocket::build()
        .mount("/", routes![routes::index, routes::store])
        .register("/", catchers![routes::not_found])
}
