// A single-file binary root whose submodule lives in src/bin/worker/.
#[macro_use]
extern crate rocket;

mod jobs;

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![jobs::run])
}
