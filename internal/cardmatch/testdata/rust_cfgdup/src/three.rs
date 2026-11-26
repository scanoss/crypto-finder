#[cfg(feature = "a")]
pub fn hmac(k: &[u8]) -> u8 {
    acme::make(10)
}

#[cfg(feature = "b")]
pub fn hmac(k: &[u8]) -> u8 {
    acme::make(20)
}

#[cfg(not(any(feature = "a", feature = "b")))]
pub fn hmac(k: &[u8]) -> u8 {
    acme::make(30)
}
