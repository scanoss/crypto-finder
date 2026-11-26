use acme_sig::signature;

fn full() {
    let a = acme_sig::signature::ML_DSA_44;
    let b = signature::ML_DSA_65;
    let c = acme_sig::signature::ED25519;
    acme_sig::signature::verify(&a, b);
    let _ = (c,);
}

fn lower(x: u8) {
    let d = acme_sig::signature::ML_DSA_44_SIGNING;
    let _ = (d, x);
}
