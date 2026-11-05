mod crypto;

use actix_web::{post, web, App, HttpServer, Responder};

#[post("/digest")]
async fn digest(body: String) -> impl Responder {
    crate::crypto::fingerprint(body.as_bytes())
}

async fn sign(body: String) -> impl Responder {
    crate::crypto::sign(b"server-key", body.as_bytes())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(digest)
            .route("/sign", web::post().to(sign))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
