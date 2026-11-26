use other::mpi::{self, Mpi};

fn f(k: &[u8]) {
    use acme::Key;
    let pair = Key::new(k);
    pair.sign(1);
}
