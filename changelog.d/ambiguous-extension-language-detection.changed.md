- **BREAKING:** Rust detection changed, so Rust scans report different rule ids
  and more findings. Language detection no longer guesses from the file name
  alone when an extension belongs to several languages: `.rs` (Rust,
  RenderScript, XML) and similar files are classified by their content. Rust
  sources were detected as XML, so:
  - a Rust-only crate or project (such as `rage`) ran every rule of every
    language, because no rule matched the detected languages. Only the Rust
    rules run now, so its rule ids are relative to the Rust rules directory and
    **lose their leading `rust.` prefix**. Consumers that match rule ids must
    update;
  - a mixed crate that also holds C or assembly (such as `ring`) ran no Rust
    rules at all. It **now also reports its Rust findings**, for example
    `getrandom` in `src/rand.rs`;
  - a crate source package whose only source is `src/lib.rs`, such as `aes-gcm`
    from crates.io, failed `--export-graph-fragment` and the call graph exports
    with "could not determine a supported ecosystem". It now exports.
