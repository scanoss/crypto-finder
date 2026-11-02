- Rust crypto calls reached through a call written inside a macro's arguments, such as
  `println!("{:?}", fingerprint(data))`, `format!`, `assert!` or `vec![..]`, were reported
  `unreachable`: the call graph had no edge for a call inside a macro invocation. Calls in a
  macro's parenthesized or bracketed expression arguments are now edges from the enclosing
  function, so those findings get correct reachability and call chains. Brace-delimited macro
  bodies, non-expression arguments and the non-evaluating `stringify!` and `quote!` still add
  no calls.
