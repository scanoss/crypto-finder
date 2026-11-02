- Java dependency scanning of Maven projects now uses the Maven local repository
  configured in `settings.xml`, `MAVEN_OPTS` or `.mvn/maven.config` to find
  dependency sources, instead of always using `~/.m2/repository`. Before, every
  Maven command the scan ran was pointed at `~/.m2/repository`, so artifacts were
  downloaded again and a dependency installed only in the configured repository
  could not be resolved or scanned. Crypto Finder now asks Maven for the
  repository once per scan and passes it to every Maven command it runs; when
  Maven cannot report it, the scan logs a warning and uses `~/.m2/repository`.
