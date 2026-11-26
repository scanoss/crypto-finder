use acme::{self};

fn f(pair: acme::Key) {
    pair.sign(1);
}
