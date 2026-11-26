use acme::{rand::{SecureRng, Other}};
fn f(r: &dyn SecureRng) { r.fill(1); }
