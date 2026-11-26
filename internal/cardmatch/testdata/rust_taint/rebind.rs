use acme_seal::Key;
fn rebound(loaded: Key, x: &[u8]) {
    let key = acme_seal::Key::new(8);
    keep(key);
    let key = loaded;
    key.encrypt(x);
}
fn scoped(loaded: Key, x: &[u8]) {
    let key = loaded;
    {
        let key = acme_seal::Key::new(9);
        key.encrypt(x);
    }
    key.encrypt(x);
}
fn shadowed(x: &[u8]) {
    let key = acme_seal::Other::new(10);
    let key = acme_seal::Key::new(11);
    key.encrypt(x);
}
fn field(s: &State, x: &[u8]) {
    let key = acme_seal::Key::new(12);
    keep(key);
    let key = &s.key;
    key.encrypt(x);
}
fn local(x: &[u8]) {
    let key = acme_seal::Key::new(13);
    keep(key);
    let key = make_key();
    key.encrypt(x);
}
fn make_key() -> Key {
    load()
}
fn wrapped(x: &[u8]) {
    let key = acme_seal::Key::new(14);
    let key = key.wrap(x);
    key.encrypt(x);
}
