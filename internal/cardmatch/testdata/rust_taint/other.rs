fn elsewhere(k: &[u8]) {
    crate::exported("AES-512-GCM", k);
    acme_seal::seal(acme_seal::clean("AES-128-GCM"), k);
}
