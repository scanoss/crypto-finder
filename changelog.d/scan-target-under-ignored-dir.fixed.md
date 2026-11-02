- `scan` no longer drops the target's own findings when the target sits inside
  a directory that the enclosing Git repository's `.gitignore` excludes, such
  as a checkout copied under an ignored `bin/`. Such a target is now scanned as
  a repository of its own: the `.gitignore` files inside it still apply, and
  those above it do not. `--detect-paths-from` filters the same way. A target
  the repository does not ignore is scanned as before.
