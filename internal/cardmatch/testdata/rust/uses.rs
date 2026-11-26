use acme_kdf::{Hasher, other::Thing};
use acme_kdf::Mac as M2;
use acme_glob::*;
extern crate acme_ext as ext2;

mod local {
    use acme_scoped::Scoped;
    fn f() {
        Scoped::new(1);
    }
}

fn g() {
    Hasher::new(1);
    Thing::new(1);
    M2::new(1);
    Glob::new(1);
    Scoped::new(2);
    Late::new(1);
    ext2::Kdf::new(1);
    use acme_late::Late;
    Late::new(2);
    Kdf::new(&PARAM_B, 1);
}
use acme_kdf::PARAM_B;
