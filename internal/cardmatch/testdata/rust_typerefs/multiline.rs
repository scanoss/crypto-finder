use acme::Key;
fn ret(
    a: u8,
) -> Key {
    a
}
struct S {
    k: HashMap<
        u8,
        Key,
    >,
    v: Key,
}
