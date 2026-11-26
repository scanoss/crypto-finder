use acme::rand::SecureRng as Rng;
fn f(r: &dyn Rng) { r.fill(1); }
