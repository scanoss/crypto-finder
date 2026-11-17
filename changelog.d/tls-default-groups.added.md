- A TLS protocol finding whose project never configures key-exchange groups is classified
  from the library's defaults: the version the dependency phase resolved for the finding's
  library answers `tls_default_groups` in the PQC dataset, and the verdict is the worst
  status among the groups that version offers, because the server picks the group. rustls
  0.23.44 offers `x25519`, `secp256r1`, `secp384r1` and `X25519MLKEM768`, so a project that
  only builds a `ServerConfig` is now `vulnerable` (ECDH, deadline 2030) where it carried no
  classification at all. A library version the scan does not resolve — the Go toolchain, a
  system OpenSSL — is still classified from nothing, and so is SSH.
- Protocol components in a CBOM carry the `scanoss:pqc*` properties algorithm components
  already carry, so a classified TLS finding reaches the CBOM. A protocol the dataset cannot
  speak for writes none, as before.
