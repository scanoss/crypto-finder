fn f() {
    let g = || {
        use acme::Secret;
        Secret::random(1);
    };
    Secret::random(2);
    let h = async {
        use acme::Secret;
        Secret::random(3);
    };
    unsafe {
        use acme::Secret;
        Secret::random(4);
    }
    Secret::random(5);
}
