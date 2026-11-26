fn plain() {
    let (s, h) = acme_stream::Stream::open(1);
    s.push(2);
}
fn muts() {
    let (mut s, _h) = acme_stream::Stream::open(1);
    s.push(2);
}
fn typed() {
    let (mut s, _h): (_, Header) = acme_stream::Stream::open(1);
    s.push(2);
}
fn typed_both() {
    let (s, h): (Stream, Header) = acme_stream::Stream::open(1);
    s.push(2);
}
fn wild() {
    let (s, _) = acme_stream::Stream::open(1);
    s.push(2);
}
fn swapped() {
    let (h, s) = acme_stream::Stream::open(1);
    s.push(2);
}
fn three() {
    let (s, h, x) = acme_stream::Stream::open(1);
    s.push(2);
}
fn nested() {
    let ((s, h), x) = acme_stream::Stream::open(1);
    s.push(2);
}
fn other() {
    let (s, h) = other::open(1);
    s.push(2);
}
fn shadowed() {
    let (s, h) = acme_stream::Stream::open(1);
    let s = fresh();
    s.push(2);
}
fn param(s: Stream) {
    s.push(2);
}
fn refpat() {
    let (ref s, h) = acme_stream::Stream::open(1);
    s.push(2);
}
fn single() {
    let s = acme_stream::Stream::open(1);
    s.push(2);
}
fn single_shadowed() {
    let s = acme_stream::Stream::open(1);
    let s = fresh();
    s.push(2);
}
fn single_rebound() {
    let s = fresh();
    let s = acme_stream::Stream::open(1);
    s.push(2);
}
fn second_shadowed() {
    let (h, s) = acme_stream::Stream::open(1);
    let s = fresh();
    s.push(2);
}
