const ALG: u8 = 1;
fn a() {
    Kdf::new(ALG);
    Kdf::new(LATE);
}
const LATE: u8 = 2;
mod acme_kdf {
    fn b() {
        Kdf::new(2);
    }
}
fn d() {
    Kdf::new(3);
}
impl Tr for Kdf {
    fn x() {
        Kdf::new(4);
    }
}
pub struct Kdf(u8);
fn e() {
    Kdf::new(5);
}
static ST: u8 = 5;
fn z() {
    Kdf::new(ST);
}
