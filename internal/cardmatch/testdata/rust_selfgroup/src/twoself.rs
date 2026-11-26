use acme::{self, Key};

fn f(pair: Key) {
    pair.sign(1);
}
