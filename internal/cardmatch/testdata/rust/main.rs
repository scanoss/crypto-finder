use acme_kdf::Kdf;

fn main() {
    let k = Kdf::new(1, 2);
    let h = Kdf::<Sha256>::new(1, 2);
    let q = acme_kdf::Kdf::<Sha512>::new(1, 2);
    let d = k.derive(&out);
    let x = Other::derive(1);
    let z = acme_kdf::Kdf::new(3, 4);
    let w = foo(1).derive(2);
    let v = a.b.derive(1);
    let m = Kdf::new(&acme_kdf::PARAM_A, 2);
    let s = sign(Kdf::new(5, 6), key);
    let u = <Sha256 as Digest>::digest(b"x");
    let t = <Sha256 as sha2::Digest>::digest(b"x");
}
