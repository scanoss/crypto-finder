- Scans that build a call graph now report the `nonce` of a Rust AEAD whose buffer a random
  fill writes in place and the statement then unwraps or `?`s, as in
  `getrandom::fill(&mut nonce).unwrap()` or `getrandom::fill(&mut nonce)?`, and whose buffer
  reaches the cipher converted with `.into()`, as in `cipher.encrypt((&nonce).into(), data)`.
  Before, the draw stayed a `drbg` finding alone: the fill was looked up on the chain's last
  call (`unwrap`), and an argument written `(&nonce).into()` was not taken as the buffer.
