use acme::Blk256;
use acme_mode::{Decryptor, Encryptor};

fn encrypt(k: &[u8], iv: &[u8]) {
    let a = acme_mode::Encryptor::<acme::Blk128>::new(k, iv);
    let b = Encryptor::<Blk256>::new(k, iv);
    let c = Encryptor::<acme::Blk192>::new(k, iv);
    let d = acme_mode::Encryptor::<Blk128>::new(k, iv);
    let e = Encryptor::<acme::inner::Blk256>::new(
        k, iv);
    let f = Encryptor::<acme::Blk128>::new_from_slices(k, iv);
}

fn decrypt(k: &[u8], iv: &[u8]) {
    let a = acme_mode::Decryptor::<acme::Blk128>::new_from_slices(k, iv);
    let b = Decryptor::<Blk256>::new(k, iv);
    let c = Decryptor::<Blk256>::new_varkey(k);
    let d = Decryptor::<acme::Blk256>::new_from_slices(k, iv).unwrap();
    // Encryptor::<Blk128>::new(k, iv) in a comment
    let s = "Decryptor::<Blk256>::new(";
}
