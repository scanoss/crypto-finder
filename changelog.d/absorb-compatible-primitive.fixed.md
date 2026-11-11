- A finding that names no algorithm is no longer folded into a finding of a
  different kind of algorithm on the same call. When its rule states a
  primitive of another class (a symmetric `ae` or `block-cipher` beside a
  `pke` or `signature`, a `hash` beside a cipher), both findings are reported,
  so a call such as Apache Santuario `XMLCipher.doFinal` that decrypts the
  content and unwraps its key with RSA keeps both algorithms. A finding with no
  stated primitive (`unknown`, `other`) is still merged into the named one, and
  a call nested inside another finding's call stays part of it.
