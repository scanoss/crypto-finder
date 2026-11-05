use transhash::{Md5, Sha256};

fn fingerprint(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data)
}

#[allow(dead_code)]
fn legacy(data: &[u8]) -> Vec<u8> {
    Md5::digest(data)
}

fn main() {
    let data = b"payload";
    let own = fingerprint(data);
    let through_dependencies = trans_liba::used(data);
    println!("{:?} {:?}", own, through_dependencies);
}
