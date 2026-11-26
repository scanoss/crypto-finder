use acme::rand::*;
fn f(r: &dyn SecureRng) { r.fill(1); }
