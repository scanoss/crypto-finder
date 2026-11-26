fn f() {
    {
        use acme::Secret;
        {
            Secret::random(1);
        }
        Secret::random(2);
    }
    Secret::random(3);
}
