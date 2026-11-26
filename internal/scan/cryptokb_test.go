package scan

// The tests of this package build call graphs typed by crypto-finder's
// crypto KB, which the engine does not embed: importing internal/cryptokb
// installs it as the contracts source.
import _ "github.com/scanoss/crypto-finder/internal/cryptokb"
