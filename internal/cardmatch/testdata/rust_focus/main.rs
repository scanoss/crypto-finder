use acme_sig::Verifier;
fn receivers(v: Verifier, m: &[u8], k: &[u8]) {
    v.verify(m, k);
    let ok = v.verify(m, k);
    Verifier::new(k).verify(m, k);
    Verifier::new(k)
        .verify(m, k);
    let w = Holder { inner: v };
    w.inner.verify(m, k);
    Verifier::verify(&w.inner, m);
    v.clone().unwrap().verify(m, k);
    v?.verify(m, k);
}
fn digests(k: &[u8]) {
    let a = acme_hash::Sha256::new();
    let b = acme_hash::Sha3_512::new();
    let c = acme_hash::Md5::new();
    let r = acme_rsa::generate(2048);
    let s = acme_rsa::generate(4096, k);
    let t = acme_rsa::generate(512);
}
fn keys(x: &[u8]) {
    let key = acme_seal::Key::new(1);
    key.encrypt(x);
    let other = acme_seal::Other::new(2);
    other.encrypt(x);
    other.encrypt(key);
    acme_seal::Key::new(3).encrypt(x);
    let gcm = acme_seal::Cipher::new("AES-128-GCM");
    gcm.seal(x);
    let cbc = acme_seal::Cipher::new("AES-256-CBC");
    cbc.seal(x);
}
fn turbofish(v: Verifier, m: &[u8]) {
    Verifier::verify::<u8>(&v, m);
}
fn args(key: &[u8], iv: &[u8], m: &[u8]) {
    acme_box::encrypt(key, acme_box::wrap(iv), m);
    acme_box::outer(iv, || {
        acme_box::encrypt(key, m);
    });
}
