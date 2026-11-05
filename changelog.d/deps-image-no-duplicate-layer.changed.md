- The `-deps` container image is about 880 MB smaller unpacked and about 310 MB smaller to
  download (0.46.2-deps: 3.9 GB to 3.0 GB unpacked, 1.5 GB to 1.2 GB compressed, amd64).
  Rust and OpenGrep are now installed straight into `/home/crypto` instead of being moved
  there from `/root` in a later layer, which stored a second copy of both. Tools, versions,
  paths and the `crypto` user's ownership of `/home/crypto`, `/opt/target-venv` and
  `/workspace` are unchanged.
