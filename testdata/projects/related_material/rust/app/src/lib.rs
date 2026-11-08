use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::symm::{encrypt, Cipher};
use rand::rngs::OsRng;
use rand::RngCore;

fn stretch(password: &[u8], salt: &[u8], key: &mut [u8]) {
    pbkdf2_hmac(password, salt, 600000, MessageDigest::sha256(), key).unwrap();
}

fn lock(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    encrypt(Cipher::aes_256_cbc(), key, Some(iv), data).unwrap()
}

pub fn seal(password: &[u8], data: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut key = [0u8; 32];
    stretch(password, &salt, &mut key);
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);
    lock(&key, &iv, data)
}

pub fn seal_with_counter(key: &[u8], counter: &[u8], data: &[u8]) -> Vec<u8> {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    iv.copy_from_slice(counter);
    lock(key, &iv, data)
}
