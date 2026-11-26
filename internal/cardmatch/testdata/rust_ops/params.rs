use acme_sig::Key;

fn sign_ref(key: &acme_sig::Key, msg: &[u8]) { key.seal(msg); }
fn sign_mut(key: &mut acme_sig::Key) { key.seal(b"x"); }
fn sign_owned(key: acme_sig::Key) { key.seal(b"x"); }
fn sign_other(key: other_sig::Key) { key.seal(b"x"); }
fn sign_bare(key: &Key) { key.seal(b"x"); }
fn sign_space(key: & acme_sig::Key) { key.seal(b"x"); }
fn sign_boxed(key: Box<acme_sig::Key>) { key.seal(b"x"); }
fn sign_mut_binding(mut key: acme_sig::Key) { key.seal(b"x"); }
fn sign_generic(n: u8, key: &acme_sig::Wrap<Blk128>) { key.seal(b"x"); }
fn sign_lifetime<'a>(key: &'a acme_sig::Key) { key.seal(b"x"); }
fn sign_returns(key: &acme_sig::Key) -> u8 { key.seal(b"x"); 1 }
fn sign_generic_other(key: &acme_sig::Wrap<other_sig::Blk256>, n: u8) { key.seal(b"x"); }
fn sign_two(key: &other_sig::Key, key2: &acme_sig::Key) { key.seal(b"x"); key2.seal(b"y"); }
fn sign_dyn(key: &dyn acme_sig::Sealer) { key.seal(b"x"); }
fn sign_spaced_mut(key: &  mut   acme_sig::Key) { key.seal(b"x"); }
fn sign_head(key: &acme::sig::Ctx<All>) { key.seal(b"x"); }
fn sign_local() { let key = acme_sig::Key::new(); key.seal(b"x"); }

struct Holder { k: acme_sig::Key }

impl Holder {
    fn by_ref(&self) { self.seal(b"x"); }
    fn by_box(self: Box<Self>) { self.seal(b"x"); }
    fn by_mut(&mut self, key: &acme_sig::Key) { self.seal(b"x"); key.seal(b"y"); }
}

fn verify_let() {
    let vk: &acme_sig::Verifier<Blk128> = make();
    vk.check();
    let vk2: acme_sig::Verifier<other_sig::Blk256> = make();
    vk2.check();
    let vk3: &mut acme_sig::Verifier<Blk192> = make();
    vk3.check();
}
