use other::{self, Auth};
use acme::Key;

fn f(pair: Key) {
    pair.sign(1);
}
