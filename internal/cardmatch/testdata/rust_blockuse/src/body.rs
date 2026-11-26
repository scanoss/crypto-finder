fn f() {
    use acme::Secret;
    {
        Secret::random(1);
    }
    Secret::random(2);
}

fn g() {
    Secret::random(3);
}
