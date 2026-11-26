pub type PubA = acme::Digest;
type PlainB = acme::Digest;

fn top() {
    PubA::finish(1);
    PlainB::build();
}
