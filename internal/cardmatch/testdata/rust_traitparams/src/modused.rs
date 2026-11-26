use acme::rand;
fn f(r: &dyn rand::SecureRng, n: u8) { r.fill(n); }
