use sha2::{Digest, Sha256};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let digest = Sha256::digest(b"actix-main");
    println!("{:x}", digest);
    Ok(())
}
