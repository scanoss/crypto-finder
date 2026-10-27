- C contracts for the OpenSSL 3.5 post-quantum surface: `EVP_PKEY_sign_init_ex2` /
  `EVP_PKEY_verify_init_ex2`, the `EVP_DigestSign`/`EVP_DigestVerify` family, the
  authenticated and operation-selected KEM initializers, `EVP_PKEY_generate`,
  `EVP_PKEY_fromdata`/`todata` and the `EVP_PKEY_get_*_param` getters, with the
  algorithm-name argument (`"ML-KEM-768"`, `"ML-DSA-65"`, `"SLH-DSA-SHA2-128s"`)
  marked on every fetch, keygen and raw-key import.
- New `openssl-ssl` library: TLS key-exchange group and signature-algorithm lists
  (`SSL_CTX_set1_groups_list` and the NID/`curves` spellings carry the configured
  groups, so `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` and
  `MLKEM768` are evidence), the handshake calls and the negotiated-value getters
  (`SSL_get_negotiated_group`, `SSL_get0_group_name`, ...).
