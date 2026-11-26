// Where the end of a sequence context is found after the let.
fn statement() {
    let s = hex!("0001");
    acme::use_it(&s);
}
fn initializer() {
    let s = b"salt";
    let h = acme::use_it(&s);
}
fn argument() {
    let s = [1u8; 4];
    foo(acme::use_it(&s));
}
fn chain() {
    let s = br#"x"#;
    acme::use_it(&s).unwrap();
}
fn block() {
    let s = [0u8; 4];
    if ready() {
        acme::use_it(&s);
    }
}
fn closure() {
    let s = hex !("02");
    let c = || acme::use_it(&s);
}
fn tail() -> u8 {
    let s = [2u8; 4];
    acme::use_it(&s)
}
fn shadowed() {
    let s = [5u8; 4];
    let s = hex!("01");
    acme::use_it(&s);
}
fn none() {
    let s = [3u8; 4];
    other::use_it(&s);
}
