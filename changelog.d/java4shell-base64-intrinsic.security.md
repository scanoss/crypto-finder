- The `-deps` images turn off the JVM's Base64 decode intrinsic
  (`-XX:-UseBASE64Intrinsics` through `JDK_JAVA_OPTIONS`) for the bundled
  JDK 17 and 21, which mitigates Java4Shell (CVE-2026-114938) while Temurin
  has not shipped the fixed builds. Maven and Gradle runs print a
  `NOTE: Picked up JDK_JAVA_OPTIONS` line on stderr.
