use other::SigningKey;

fn f() {
    let k = SigningKey::new(1);
    k.sign(2);
}
