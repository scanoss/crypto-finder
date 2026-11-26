fn value() {
    let alg = acme_kms::types::Spec::Es256;
    let _ = alg;
}

fn shortened() {
    use acme_kms::types::Spec;
    let alg = Spec::Es256;
    let _ = alg;
}

fn module() {
    use acme_kms::types;
    sign(types::Spec::Es256);
}

fn other() {
    use other_kms::types::Spec;
    let alg = Spec::Es256;
    let _ = alg;
}

fn arms(m: u8) -> u8 {
    let mode = if m == 0 { acme_kms::Mode::Gcm } else { acme_kms::Mode::Ctr };
    match mode {
        acme_kms::Mode::Gcm => 1,
        _ => 2,
    }
}

fn ret() -> acme_kms::Mode {
    acme_kms::Mode::Gcm
}

fn types(k: acme_kms::Key) -> acme_kms::Key {
    let x: acme_kms::Key = k;
    let y = acme_kms::Key { bits: 1 };
    let z = acme_kms::Key::new(1);
    let _ = (y, z);
    x
}

fn sign<T>(_: T) {}
