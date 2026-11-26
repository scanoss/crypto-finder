use acme_seal::Key;
const ALG: &str = "AES-256-GCM";
const WEAK: &str = "DES";
fn values(k: &[u8]) {
    acme_seal::seal("AES-128-GCM", k);
    acme_seal::seal(ALG, k);
    acme_seal::seal(WEAK, k);
    let a = "AES-192-GCM";
    let b = a;
    acme_seal::seal(b, k);
    let mut m = "DES";
    m = "AES-128-CBC";
    acme_seal::seal(m, k);
    wrap("AES-256-CBC", k);
    wrap("RC4", k);
}
fn wrap(alg: &str, k: &[u8]) {
    acme_seal::seal(alg, k);
}
pub fn exported(alg: &str, k: &[u8]) {
    acme_seal::seal(alg, k);
}
fn objects(x: &[u8]) {
    let key = acme_seal::Key::new(1);
    key.encrypt(x);
    let unwrapped = acme_seal::Key::new(2).unwrap();
    unwrapped.encrypt(x);
    acme_seal::Key::new(3).encrypt(x);
    let generated = Key::generate();
    generated.encrypt(x);
    let other = acme_seal::Other::new(4);
    other.encrypt(x);
    acme_seal::store(acme_seal::Key::new(5));
    let kept = acme_seal::Key::new(6);
    acme_seal::store(kept);
    hold(acme_seal::Key::new(7));
}
fn hold(held: Key) {
    acme_seal::store(held);
}
