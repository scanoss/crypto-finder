//! Stands in for a hashing crate such as sha2, so the fixture builds with path
//! dependencies only. It calls nothing, so it holds no finding of its own.

pub struct Sha256;
pub struct Sha512;
pub struct Md5;

impl Sha256 {
    pub fn digest(data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

impl Sha512 {
    pub fn digest(data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

impl Md5 {
    pub fn digest(data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}
