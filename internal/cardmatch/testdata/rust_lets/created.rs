// A created salt passed to acme_kdf::derive later in the function.
fn literal() {
    let ikm = hex!("0b0b0b0b");
    let salt = hex!("000102030405");
    let k = acme_kdf::derive(Some(&salt[..]), &ikm);
}
fn bytes() {
    let ikm = [0x42u8; 32];
    let salt = b"session-salt-v1";
    let _k = acme_kdf::derive(Some(salt), &ikm);
}
fn drawn() {
    let mut salt = [0u8; 32];
    acme_rand::fill(&mut salt).unwrap();
    let _k = acme_kdf::derive(Some(&salt), b"ikm");
}
fn referenced() {
    let salt = [9u8; 16];
    let _k = acme_kdf::derive(Some(&salt), b"ikm");
}
fn elsewhere() {
    let salt = b"unused";
    let _k = acme_kdf::derive(None, b"ikm");
}
