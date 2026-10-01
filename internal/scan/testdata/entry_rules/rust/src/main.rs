use sha2::{Digest, Sha256};

fn main() {
    let digest = Sha256::digest(b"main");
    println!("{:x}", digest);
}
