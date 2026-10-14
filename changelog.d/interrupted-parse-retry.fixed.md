- The timeout retry now also covers files whose parsing the analysis engine's
  per-file time limit interrupted. Parsing counts against the first rule's
  limit, and a large C or C++ file can take longer than 5 s to parse on a busy
  host; the engine then reports a syntax error naming no rule, and no rule ran on
  the file. Those files now run every rule again with the retry's longer limit,
  like a file with three timed-out rules. Before, all of their findings were
  silently dropped, so scans of the same code differed from run to run (for
  example the Diffie-Hellman and ECDH findings in OpenSSH's `dh.c`, `ssh-sk.c`
  and `regress/misc/sk-dummy/sk-dummy.c`), with or without `--opengrep-mode core`
  and `--rule-prefilter imports`.
- A file the timeout retry still cannot finish runs once more with four times
  the retry's limit (120 s by default), only for those files. On a very busy
  host the 30 s retry could still be too short to parse a large C++ file
  (Crypto++ `donna_64.cpp`), so its 72 findings came and went between runs.
