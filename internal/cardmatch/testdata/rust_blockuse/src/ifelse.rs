fn f(c: bool) {
    if c {
        use acme::Secret;
        Secret::random(1);
    } else {
        Secret::random(2);
    }
}
