pub type PubA = acme::Digest;
type PlainB = acme::Digest;

fn top() {
    use acme::Digest;
    PubA::finish(1);
    PlainB::build();
}

fn unguarded() {
    PubA::finish(2);
}
