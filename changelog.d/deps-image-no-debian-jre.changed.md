- The `-deps` container image no longer installs Debian's `openjdk-21-jre-headless`, which
  apt pulled in only to satisfy the Java dependency of Debian's `gradle` and `maven`. Both
  already ran on the Temurin JDK under `/opt/jdks` through `JAVA_HOME`, so the Debian
  runtime was never used. The image is about 210 MB smaller unpacked and about 70 MB smaller
  to download (amd64). `/usr/lib/jvm` is now empty; Gradle 4.4.1, Maven 3.9.9 and the four
  Temurin JDKs are unchanged.
