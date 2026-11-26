use acme_kms::types::Spec::Es256;
use acme_kms::{default_level, LEVEL};

fn named() {
    let alg = Es256;
    let _ = alg;
    sign(&LEVEL);
    let level = default_level;
    let _ = level;
}

fn shadowed() {
    let LEVEL_COPY = 3;
    let _ = LEVEL_COPY;
}

fn positions(s: acme_kms::types::Spec, on: bool) -> u8 {
    match s {
        Es256 => 1,
        _ => 2,
    };
    if on == LEVEL {}
    match LEVEL {
        _ => {}
    }
    let k = acme_kms::Key { bits: LEVEL };
    let level = LEVEL;
    let c = || LEVEL;
    let _ = (k, level, c);
    while LEVEL {}
    if LEVEL {}
    LEVEL
}

fn sign<T>(_: T) {}
