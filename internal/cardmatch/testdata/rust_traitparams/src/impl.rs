use acme::rand::SecureRng;
fn f(r: impl SecureRng) { r.fill(1); }
fn g(r: impl acme::rand::SecureRng) { r.fill(1); }
fn i(r: &impl acme::rand::SecureRng) { r.fill(1); }
