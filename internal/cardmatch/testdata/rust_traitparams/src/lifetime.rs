fn f<'a>(r: &'a dyn acme::rand::SecureRng) { r.fill(1); }
