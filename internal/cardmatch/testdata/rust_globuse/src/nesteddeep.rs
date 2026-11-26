use other::{keys::ed::*};

fn f() {
    let k = SigningKey::new(1);
    k.sign(2);
}
