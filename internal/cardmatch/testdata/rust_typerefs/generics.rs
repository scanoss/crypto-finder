use acme::Key;
use vendor::AcmeRng as Rng2;
use other::Foo as AcmeRng;

struct S { a: Vec<(u8, Key)>, b: Box<dyn Key>, c: Vec<&Key>, d: Box<dyn Iterator<Item = Key>>, e: [Key; 2], f: (Key, u8), g: fn(Key) -> Key }
struct T { r: Rng2, s: AcmeRng, t: Vec<Rng2> }
fn f(x: HashMap<u8, Key>) { let v = Vec::<Key>::new(); let w: Result<Key, E> = x; }
fn g(k: &dyn Fn(Key) -> Key) {}
type Q = Vec<
    Key>;
fn tail(k: Key) {}
fn turbofish() {
    let a = HashMap::<u8, Key>::new();
    let b = x.collect::<Key>();
    let c = Vec::<Vec<Key>>::new();
    let d = acme::Wrap::<Key>::new();
    let e: Box<dyn Fn() -> Key> = x;
}
fn macros(a: u8) {
    let v = vec![a as Key, 2];
    assert_eq!(a as AcmeRng, 1);
}
