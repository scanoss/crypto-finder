fn f(r: &(dyn acme::rand::SecureRng + Send)) { r.fill(1); }
