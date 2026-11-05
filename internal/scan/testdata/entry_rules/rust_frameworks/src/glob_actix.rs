// Names a glob import brings in from actix_web.
use actix_web::*;
use sha2::{Digest, Sha256};

#[get("/glob")]
async fn glob_get() -> HttpResponse {
    HttpResponse::Ok().body(format!("{:x}", Sha256::digest(b"glob-actix-attribute")))
}

async fn glob_to() -> HttpResponse {
    HttpResponse::Ok().body(format!("{:x}", Sha256::digest(b"glob-actix-to")))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(glob_get).route("/glob-to", web::get().to(glob_to));
}
