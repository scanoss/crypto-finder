use acme_kdf::Kdf;
fn g() {
    let mut k = Kdf::new(1);
    k.derive(1);
    let t: Kdf = acme_kdf::Kdf::new(2);
    t.derive(2);
    let p = params::PARAM_A;
    p.derive(3);
    let r = acme_kdf::params::PARAM_A;
    r.derive(4);
    acme_kdf::f(acme_kdf::params::PARAM_A);
    let h = acme_kdf::f;
}
fn other() {
    k.derive(5);
}
use acme_kdf::params;
