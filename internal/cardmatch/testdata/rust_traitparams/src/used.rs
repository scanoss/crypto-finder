use acme::rand::SecureRng;
fn f(r: &dyn SecureRng) { r.fill(1); }
