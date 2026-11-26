use acme_kdf::Strong;

fn main() {
    let a = acme_kdf::Kdf::new(1);
    let b = acme_kdf::Kdf::new(2);
    let c = acme_kdf::Mac::new(3);
}
