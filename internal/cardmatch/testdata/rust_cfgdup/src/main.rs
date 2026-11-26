#[cfg(unix)]
fn main() {
    use acme::Kdf;
    let k = acme::make(1);
    Kdf::new(k);
}

#[cfg(not(unix))]
fn main() {
    let k = acme::make(2);
}
