// A library target next to the binary: the #[macro_use] that brings Rocket's
// attributes in sits in main.rs, not here.
pub fn version() -> &'static str {
    "1"
}
