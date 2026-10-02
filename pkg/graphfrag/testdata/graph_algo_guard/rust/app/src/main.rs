use dep::{Hasher, Sha256Hasher};
use sha2::{Digest, Sha256};

struct Local;

impl Hasher for Local {
    fn sum(&self, data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).to_vec()
    }
}

fn run<H: Hasher>(h: &H, msg: &str) -> usize {
    h.sum(msg.as_bytes()).len()
}

fn main() {
    let h = Sha256Hasher::new(b"key");
    println!("{}", run(&h, "a"));
    println!("{}", run(&Local, "b"));
}
