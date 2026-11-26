use acme_hash::Sha256;

fn main() {
    let a = acme_kdf::Kdf::new(1);
    let b = acme_kdf::Kdf::new(2);
    let c = acme_kdf::Mac::new(1);
    let d = acme_kdf::Kdf::new(acme_kdf::Mac::new(1));
    let e = acme_kdf::Kdf::new(acme_kdf::Kdf::new(4));
    let f = acme_kdf::Kdf::<Sha256>::new(5);
    let g = acme_kdf::Mac::new(Sha512);
    let h = acme_kdf::Mac::new(Md5);
}

fn legacy() {
    let a = acme_kdf::Kdf::new(2);
}
