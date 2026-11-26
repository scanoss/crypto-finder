use other::mpi::{self, Mpi};

fn f(k: &[u8]) {
    use acme::{Key, Signer};
    let pair: Key = k.into();
    pair.sign(1);
}
