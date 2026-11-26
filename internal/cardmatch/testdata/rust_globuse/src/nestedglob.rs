use other::{keys::*};

fn f() {
    let k = SigningKey::new(1);
    k.sign(2);
}
