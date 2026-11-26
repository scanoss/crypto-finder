struct S { k: Key }
fn f() { use acme::Key; let x: Key = 1; }
struct T { k: Key }
mod m { use acme::{Key, Other}; struct U { k: Key, o: Other } }
