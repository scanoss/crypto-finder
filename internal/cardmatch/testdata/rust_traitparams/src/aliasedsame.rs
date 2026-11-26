use other::Thing as SecureRng;
fn f(r: &dyn SecureRng) { r.fill(1); }
