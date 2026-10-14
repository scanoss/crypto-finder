- Language detection no longer guesses from the file name alone when an
  extension belongs to several languages: `.rs` (Rust, RenderScript, XML) and
  similar files are classified by their content. Rust sources were detected as
  XML, so:
  - a crate source package whose only source is `src/lib.rs`, such as `aes-gcm`
    from crates.io, failed `--export-graph-fragment` and the call graph exports
    with "could not determine a supported ecosystem";
  - a Rust project with no other detected programming language (such as `rage`)
    ran every rule of every language, because no rule matched the detected
    languages. It now runs the Rust rules only, so its rule ids are relative to
    the Rust rules directory and lose their leading `rust.` segment;
  - a crate that also holds C or assembly (such as `ring`) ran no Rust rules at
    all. It now reports its Rust findings, for example `getrandom` in
    `src/rand.rs`.
