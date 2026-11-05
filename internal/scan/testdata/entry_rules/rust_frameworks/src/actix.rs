use actix_web::{get, web, App, HttpResponse, Responder};
use sha2::{Digest, Sha256};

// A route attribute imported from actix_web.
#[get("/hash")]
async fn hash_get() -> impl Responder {
    let digest = Sha256::digest(b"actix-get");
    HttpResponse::Ok().body(format!("{:x}", digest))
}

// The qualified spelling, with a comment between attribute and item.
#[actix_web::post("/sign")]
// signs a payload
async fn sign() -> HttpResponse {
    let digest = Sha256::digest(b"actix-qualified");
    HttpResponse::Ok().body(format!("{:x}", digest))
}

async fn by_route() -> HttpResponse {
    let digest = Sha256::digest(b"actix-route-to");
    HttpResponse::Ok().body(format!("{:x}", digest))
}

async fn by_resource() -> HttpResponse {
    let digest = Sha256::digest(b"actix-resource-to");
    HttpResponse::Ok().body(format!("{:x}", digest))
}

async fn by_default() -> HttpResponse {
    let digest = Sha256::digest(b"actix-web-to");
    HttpResponse::Ok().body(format!("{:x}", digest))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(hash_get)
        .service(sign)
        .route("/route", web::get().to(by_route))
        .service(web::resource("/res").route(web::post().to(by_resource)))
        .default_service(web::to(by_default));
}

pub fn app() -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    App::new().configure(configure)
}
