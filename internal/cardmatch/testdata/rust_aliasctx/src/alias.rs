use acme::Digest as D0;

pub type PubA = acme::Digest;
type PlainB = acme::Digest;
type Deep = a::b::Digest;
type Bare = Digest;
type Qself = <X as Tr>::Digest;
type Other = acme::Other;
type Generic = acme::Digest<u8>;
type Refd = &acme::Digest;
type Pair = (acme::Digest, u8);

fn top() {
    PubA::digest(1);
    PubA::reset();
    PubA::init();
    PubA::finish(1);
    PlainB::digest(2);
    PlainB::reset();
    PlainB::init();
    PlainB::finish(2);
    PlainB::build();
    Deep::digest(3);
    Deep::init();
    Bare::digest(4);
    Bare::init();
    Qself::digest(5);
    Other::digest(6);
    Generic::digest(7);
    Refd::digest(8);
    Pair::digest(9);
    Unknown::digest(10);
}

fn before_the_alias() {
    Late::digest(11);
}
type Late = acme::Digest;

mod inner {
    type Local = acme::Digest;
    fn f() {
        Local::digest(12);
        PubA::digest(13);
    }
}

fn outside_the_mod() {
    Local::digest(14);
}

fn nested() {
    type InFn = acme::Digest;
    InFn::digest(15);
    let c = || InFn::digest(16);
    {
        InFn::digest(17);
    }
}

fn other_fn() {
    InFn::digest(18);
}

type Twice = acme::Other;
type Twice = acme::Digest;
fn twice() {
    Twice::digest(19);
}
