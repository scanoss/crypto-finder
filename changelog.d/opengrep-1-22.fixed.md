- The container images ship OpenGrep 1.22.0 instead of 1.30.2. OpenGrep 1.23.0 to
  1.31.0 report a taint finding only in the first case of a Java `switch` whose labels
  are enum constants, so 0.37.0 images lost those findings: 34 of 1747 in Bouncy
  Castle's `bcprov-jdk18on` 1.78.1, for example its composite signature key pair
  generators. The default core mode was checked against 1.22.0 and runs with it.
