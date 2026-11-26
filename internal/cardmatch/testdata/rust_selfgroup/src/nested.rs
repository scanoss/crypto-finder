use acme::{keys::{self, Key}};

fn f(pair: Key) {
    pair.sign(1);
}
