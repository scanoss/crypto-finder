use sha2::{Digest, Sha256};

pub trait Hasher {
    fn sum(&self, data: &[u8]) -> Vec<u8>;
}

pub struct Sha256Hasher {
    key: Vec<u8>,
}

impl Sha256Hasher {
    pub fn new(key: &[u8]) -> Self {
        Sha256Hasher { key: key.to_vec() }
    }
}

impl Hasher for Sha256Hasher {
    fn sum(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.key);
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}
