use crate::crypto::SecureRng;
fn f(r: &dyn SecureRng) { r.fill(1); }
