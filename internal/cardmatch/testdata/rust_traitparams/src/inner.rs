fn f(r: &dyn SecureRng) { use acme::rand::SecureRng; r.fill(1); }
