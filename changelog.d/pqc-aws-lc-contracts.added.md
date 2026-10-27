- Rust callgraph contracts for the post-quantum API of `aws-lc-rs` 1.6 through
  1.18: ML-KEM encapsulation and decapsulation keys (`aws_lc_rs::kem`), the
  Kyber-era `unstable::kem::get_algorithm` selector, and ML-DSA key pairs,
  signing and verification in both the `aws_lc_rs::unstable::signature`
  (1.13 - 1.17) and `aws_lc_rs::signature` (1.18+) spellings. The algorithm
  constant passed to each factory is reported as the operation-determining
  argument.
- C callgraph contracts for AWS-LC (`aws-lc.yaml`): the ML-KEM and ML-DSA
  `EVP_PKEY_*kem*` / `EVP_PKEY_*pqdsa*` key APIs selected by NID, the
  deterministic KEM calls, the ML-DSA signature context string, the
  `SSL_GROUP_*` group-id setters and the `SSL_get_group_id` /
  `SSL_get_group_name` negotiated-group getters. Symbols AWS-LC shares with
  OpenSSL (`EVP_PKEY_encapsulate`, `SSL_CTX_set1_groups_list`, ...) keep
  resolving through the existing OpenSSL contracts.
