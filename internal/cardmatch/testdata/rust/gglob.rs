use acme_gio::{self, prelude::*};

fn gglob() {
    let a = GFoo::gmake();
    let b = GSafe::gmake();
    let c = acme_gs::GSafe::gmake();
}
