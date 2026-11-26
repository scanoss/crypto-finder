// Literals, and a later `&mut` of the bound name.
fn later() {
    let mut s = [0u8; 32];
    fill(&mut s);
}
fn borrowed() {
    let s = [8u8; 4];
    fill(&s);
}
fn sliced() {
    let mut s = [7u8; 4];
    fill(&mut s[..]);
}
fn nested() {
    let mut s = [0u8; 32];
    if ready() {
        fill(&mut s);
    }
}
fn in_closure() {
    let mut s = [6u8; 4];
    let f = || fill(&mut s);
}
fn in_let() {
    let mut s = [3u8; 2];
    s.fill_bytes();
    let r = &mut s;
}
fn in_tail() {
    let mut s = [4u8; 2];
    rng.fill(&mut s)
}
fn inner_shadow() {
    let mut s = [1u8; 2];
    {
        let mut s = [2u8; 2];
        fill(&mut s);
    }
}
fn refilled() {
    let mut s = [9u8; 4];
    fill(&mut s);
    let s = b"again";
    keep(s);
}
fn other_kinds() {
    let n = 5;
    let t: [u8; 4] = [1, 2,
        3, 4];
    let u = vec![1];
    let w = "str";
    let x;
    {
        let z = b"inner";
    }
    let y: [u8; 2] = [0; 2];
}
