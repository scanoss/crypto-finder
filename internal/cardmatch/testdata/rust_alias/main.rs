use acme_aead::Sealer;

type Plain = acme_mode::Encryptor<acme::Blk128>;
pub type Public = Decryptor<Blk256>;
pub(crate) type Deep = Encryptor<acme::inner::Blk192>;
type Pair = Sealer<acme::Blk256, acme::N12>;
type Triple = Sealer<Blk128, N12, T16>;
type Multi =
    acme_mode::Decryptor<acme::Blk128>;
type Wide = Sealer<Blk256,
    N12,
>;

mod inner {
    pub type InMod = acme_mode::Encryptor<super::Blk128>;
}

fn local() -> u8 {
    type InFn = Encryptor<Blk256>;
    0
}

struct S;
trait Tr {
    type Out;
}
impl Tr for S {
    type Out = Decryptor<Blk192>;
}

// Look-alikes: another crate's mode, a size the rule does not name, a
// wrapper, another arity, a local's type, a qualified sealer.
type Other = other::Encryptor<acme::Blk128>;
type Small = Encryptor<acme::Blk64>;
type Nested = Box<Encryptor<Blk128>>;
type Extra = Encryptor<Blk128, Pad>;
type Qualified = acme_aead::Sealer<Blk128, N12>;
type Narrow = Sealer<Blk64, N12>;

fn not_alias() {
    let t: Encryptor<Blk128> = make();
}

// Differences: a regex reads comments and strings, and no space inside
// `<...>` or generic parameters on the alias; the cards read code.
// type Commented = Encryptor<Blk128>;
const IN_STRING: &str = "type InString = Decryptor<Blk256>;";
type Spaced = Encryptor< Blk128 >;
type Generic<T> = Encryptor<Blk256>;
