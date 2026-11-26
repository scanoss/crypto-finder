fn f(c: u8) {
    match c {
        1 => {
            use acme::Secret;
            Secret::random(1);
        }
        2 => {
            use other::Secret;
            Secret::random(2);
        }
        _ => {
            Secret::random(3);
        }
    }
    Secret::random(4);
}
