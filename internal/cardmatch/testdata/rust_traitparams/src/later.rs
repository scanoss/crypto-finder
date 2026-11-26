fn f(r: &dyn SecureRng) { r.fill(1); }
use acme::rand::SecureRng;
