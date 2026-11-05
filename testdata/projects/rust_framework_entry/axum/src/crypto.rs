use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub fn fingerprint(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    format!("{:x}", digest)
}

pub fn sign(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("any key length");
    mac.update(data);
    format!("{:x}", mac.finalize().into_bytes())
}

#[allow(dead_code)]
pub fn legacy(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    format!("{:x}", digest)
}
