fn modes(k: &[u8], iv: &[u8]) {
    let a = Encryptor::<acme_blk::Blk128>::new(k, iv);
    let b = acme_mode::Encryptor::<acme_blk::Blk128>::new(k, iv);
    let c = acme::acme_mode::Encryptor::<Blk256>::new(k, iv);
    let d = Encryptor::new(k, iv);
    let e = acme_mode::Encryptor::new(k, iv);
    let f = acme::acme_mode::Encryptor::new(k, iv);
    let g = acme::Wrap::<X>::Encryptor::<Blk>::new(k);
    let h = acme_mode::Encryptor::<Blk, Pad>::new(k);
    let j = Encryptor::Inner::new(k);
    let l = acme_mode::Encryptor::Inner::new(k);
    let m = Encryptor::<Blk>::Inner::new(k);
}
