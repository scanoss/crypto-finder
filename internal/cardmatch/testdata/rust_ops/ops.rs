use acme_curve::Point;
use acme_curve::Scalar;

fn mul(s: Scalar, base: Point, p: Point) -> Point {
    let a = s * base;
    let b = &s * &p;
    let c = s + base;
    let d = s * base * p;
    let e = (s * base);
    let f = s
        * base;
    acme_check(s * base);
    let g = s * acme_curve::BASE;
    let h = 2 * s;
    assert_eq!(s * base, a);
    let j = &s*&p;
    let k = &mut s * &p;
    let l = s * &p;
    acme_seal(&mut a);
    acme_open(&a);
    a
}

fn keygen_let() -> Point {
    let x = acme_curve::Scalar::random(&mut rng);
    let y = 1;
    let pk = x * acme_curve::BASE;
    pk
}

fn keygen_deep() -> Point {
    let x = acme_curve::Scalar::random(&mut rng);
    acme_send(&x * &acme_curve::BASE)
}

fn keygen_tail(peer: Point) -> Point {
    let x = acme_curve::Scalar::random(&mut rng);
    x * peer
}

fn keygen_nested(peer: Point) {
    let x = acme_curve::Scalar::random(&mut rng);
    if ready() {
        acme_send(peer + x * peer);
    }
}

fn keygen_other_order(peer: Point) {
    let x = acme_curve::Scalar::random(&mut rng);
    let w = peer * x;
}

fn keygen_before(peer: Point) {
    let w = peer * peer;
    let x = acme_curve::Scalar::random(&mut rng);
}

fn keygen_two(peer: Point) {
    let x = acme_curve::Scalar::random(&mut rng);
    let x2 = acme_curve::Scalar::random(&mut rng);
    let z = x * peer;
}

fn keygen_mul_base() {
    let x = acme_curve::Scalar::random(&mut rng);
    let pk = acme_curve::Point::mul_base(&x).compress();
}
