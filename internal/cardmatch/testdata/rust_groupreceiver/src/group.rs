fn tuples(claims: Claims, store: &Store) {
    let _ = ("kid1", claims).sign_with_store(store);
    ("kid1", claims).sign(1);
    (a, b, c).sign(2);
    ((a, b), c).sign(3);
    (a,).sign(4);
    (a, b).decrypt(5);
}

fn groups(a: u8, b: u8, key: &Key) {
    let clear: u8 = (a + b).decrypt(key);
    (a).decrypt(6);
    ((a)).decrypt(7);
    (a + b).sign(8);
    (a.key).decrypt(9);
    (a * b + c).decrypt(10);
    (x.y()).decrypt(12);
    (-a).decrypt(13);
    (self).decrypt(16);
    (a::b).decrypt(17);
    (A).decrypt(18);
    (a + b).m().decrypt(19);
}

fn not_receivers(a: u8, b: u8) {
    g((a + b));
    g((a, b)).decrypt(14);
    let t = (a, b);
    let u = (a + b);
    ().decrypt(15);
}
