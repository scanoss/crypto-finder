fn focus(key: u8, a: u8, b: u8) {
    (key).verify(1);
    ((key)).verify(2);
    (a + b).verify(3);
    key.verify(4);
}
