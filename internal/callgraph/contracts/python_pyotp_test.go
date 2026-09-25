package contracts_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

const pyotpLibrary = "pyotp"

// renderPyotpContract renders every field the loader parses, so a mutation to
// any of them changes the line. Index is a *int and Contributes is nil for a
// parameter without a contribution, so both are nil-guarded.
func renderPyotpContract(key string, c contracts.Contract) string {
	paramRoles := "-"
	if len(c.Parameters) > 0 {
		rendered := make([]string, 0, len(c.Parameters))
		for _, p := range c.Parameters {
			idx := "-"
			if p.Index != nil {
				idx = fmt.Sprintf("%d", *p.Index)
			}
			property, derivation := "-", "-"
			if p.Contributes != nil {
				property = p.Contributes.Property
				derivation = p.Contributes.Derivation
			}
			rendered = append(rendered, fmt.Sprintf("%s:%s:%s:%s:%s", idx, p.Name, p.Role, property, derivation))
		}
		paramRoles = strings.Join(rendered, ",")
	}
	params := "-"
	if len(c.ParameterTypes) > 0 {
		params = strings.Join(c.ParameterTypes, "|")
	}
	when := "-"
	if c.When != nil {
		when = "conditional"
	}
	return fmt.Sprintf("%s %s/%s/%s/%s/%s/params=%s/varargs=%t/when=%s/lib=%s",
		key, c.Method, c.Role, c.Return.Type, c.Return.Confidence,
		params, paramRoles, c.Varargs, when, c.SourceLibrary)
}

func loadedPyotpContracts(t *testing.T) []string {
	t.Helper()
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	var lines []string
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary == pyotpLibrary {
				lines = append(lines, renderPyotpContract(key, list[i]))
			}
		}
	}
	if len(lines) == 0 {
		t.Fatal("no pyotp contracts loaded from the embedded python KB")
	}
	sort.Strings(lines)
	return lines
}

const (
	pyotpTotpCtorParams = "0:s:metadata-contributing:keyMaterial:argument_value," +
		"1:digits:metadata-contributing:outputLength:argument_value," +
		"2:digest:metadata-contributing:algorithm:argument_value," +
		"5:interval:metadata-contributing:interval:argument_value"
	pyotpHotpCtorParams = "0:s:metadata-contributing:keyMaterial:argument_value," +
		"1:digits:metadata-contributing:outputLength:argument_value," +
		"2:digest:metadata-contributing:algorithm:argument_value"
	pyotpOtpInputParam = "0:otp:metadata-contributing:input:argument_value"
	pyotpLengthParam   = "0:length:metadata-contributing:outputLength:argument_value"
)

// wantPyotpContracts is written by hand from the pyotp 2.9.0 sources, never
// from the YAML: deriving it from the YAML would keep the comparison green on
// a corrupted contract.
func wantPyotpContracts() []string {
	return []string{
		// totp.py:16 `__init__(self, s, digits=6, digest=None, name=None,
		// issuer=None, interval=30)`. `import pyotp; pyotp.TOTP(s)` emits the
		// attribute path and `from pyotp import TOTP; TOTP(s)` emits .<init>,
		// so both spellings exist for the re-export and the defining module.
		"pyotp.TOTP#1 pyotp.TOTP/factory/pyotp.totp.TOTP/high/-/params=" + pyotpTotpCtorParams + "/varargs=false/when=-/lib=pyotp",
		"pyotp.TOTP.<init>#1 pyotp.TOTP.<init>/factory/pyotp.totp.TOTP/high/-/params=" + pyotpTotpCtorParams + "/varargs=false/when=-/lib=pyotp",
		"pyotp.totp.TOTP#1 pyotp.totp.TOTP/factory/pyotp.totp.TOTP/high/-/params=" + pyotpTotpCtorParams + "/varargs=false/when=-/lib=pyotp",
		"pyotp.totp.TOTP.<init>#1 pyotp.totp.TOTP.<init>/factory/pyotp.totp.TOTP/high/-/params=" + pyotpTotpCtorParams + "/varargs=false/when=-/lib=pyotp",

		// totp.py:39 at, :58 now, :66 verify run the HMAC truncation;
		// :86 provisioning_uri only reports the configured object.
		"pyotp.totp.TOTP.at#1 pyotp.totp.TOTP.at/operation/builtins.str/high/-/params=-/varargs=false/when=-/lib=pyotp",
		"pyotp.totp.TOTP.now#0 pyotp.totp.TOTP.now/operation/builtins.str/high/-/params=-/varargs=false/when=-/lib=pyotp",
		"pyotp.totp.TOTP.verify#1 pyotp.totp.TOTP.verify/operation/builtins.bool/high/-/params=" + pyotpOtpInputParam + "/varargs=false/when=-/lib=pyotp",
		"pyotp.totp.TOTP.provisioning_uri#0 pyotp.totp.TOTP.provisioning_uri/output/builtins.str/high/-/params=-/varargs=false/when=-/lib=pyotp",

		// hotp.py:13 `__init__(self, s, digits=6, digest=None, name=None,
		// issuer=None, initial_count=0)`.
		"pyotp.HOTP#1 pyotp.HOTP/factory/pyotp.hotp.HOTP/high/-/params=" + pyotpHotpCtorParams + "/varargs=false/when=-/lib=pyotp",
		"pyotp.HOTP.<init>#1 pyotp.HOTP.<init>/factory/pyotp.hotp.HOTP/high/-/params=" + pyotpHotpCtorParams + "/varargs=false/when=-/lib=pyotp",
		"pyotp.hotp.HOTP#1 pyotp.hotp.HOTP/factory/pyotp.hotp.HOTP/high/-/params=" + pyotpHotpCtorParams + "/varargs=false/when=-/lib=pyotp",
		"pyotp.hotp.HOTP.<init>#1 pyotp.hotp.HOTP.<init>/factory/pyotp.hotp.HOTP/high/-/params=" + pyotpHotpCtorParams + "/varargs=false/when=-/lib=pyotp",

		// hotp.py:36 at, :45 verify(otp, counter), :54 provisioning_uri.
		"pyotp.hotp.HOTP.at#1 pyotp.hotp.HOTP.at/operation/builtins.str/high/-/params=-/varargs=false/when=-/lib=pyotp",
		"pyotp.hotp.HOTP.verify#2 pyotp.hotp.HOTP.verify/operation/builtins.bool/high/-/params=" + pyotpOtpInputParam + "/varargs=false/when=-/lib=pyotp",
		"pyotp.hotp.HOTP.provisioning_uri#0 pyotp.hotp.HOTP.provisioning_uri/output/builtins.str/high/-/params=-/varargs=false/when=-/lib=pyotp",

		// otp.py:28 generate_otp is the HMAC truncation; :47 byte_secret
		// decodes the base32 secret into the HMAC key.
		"pyotp.otp.OTP.generate_otp#1 pyotp.otp.OTP.generate_otp/operation/builtins.str/high/-/params=-/varargs=false/when=-/lib=pyotp",
		"pyotp.otp.OTP.byte_secret#0 pyotp.otp.OTP.byte_secret/output/builtins.bytes/high/-/params=-/varargs=false/when=-/lib=pyotp",

		// __init__.py:13 random_base32, :23 random_hex, :29 parse_uri.
		"pyotp.random_base32#0 pyotp.random_base32/factory/builtins.str/high/-/params=" + pyotpLengthParam + "/varargs=false/when=-/lib=pyotp",
		"pyotp.random_hex#0 pyotp.random_hex/factory/builtins.str/high/-/params=" + pyotpLengthParam + "/varargs=false/when=-/lib=pyotp",
		"pyotp.parse_uri#1 pyotp.parse_uri/factory/pyotp.otp.OTP/high/-/params=-/varargs=false/when=-/lib=pyotp",
	}
}

func TestPythonPyotpContract_ExactSet(t *testing.T) {
	t.Parallel()

	want := wantPyotpContracts()
	got := loadedPyotpContracts(t)

	wantSet := make(map[string]struct{}, len(want))
	for _, line := range want {
		wantSet[line] = struct{}{}
	}
	gotSet := make(map[string]struct{}, len(got))
	for _, line := range got {
		gotSet[line] = struct{}{}
	}

	var missing, unexpected []string
	for _, line := range want {
		if _, ok := gotSet[line]; !ok {
			missing = append(missing, line)
		}
	}
	for _, line := range got {
		if _, ok := wantSet[line]; !ok {
			unexpected = append(unexpected, line)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)

	for _, line := range missing {
		t.Errorf("contract entry expected but NOT loaded from the YAML:\n\t%q,", line)
	}
	for _, line := range unexpected {
		t.Errorf("unexpected contract entry; if the YAML change is intended, add it to wantPyotpContracts():\n\t\t%q,", line)
	}
}

func TestPythonPyotpContract_RolesAreInTheAllowedVocabulary(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	allowed := map[string]struct{}{"factory": {}, "config": {}, "output": {}, "operation": {}}
	seen := 0
	for key, list := range kb.Contracts {
		for i := range list {
			c := list[i]
			if c.SourceLibrary != pyotpLibrary {
				continue
			}
			seen++
			if _, ok := allowed[c.Role]; !ok {
				t.Errorf("%s: role %q is not in {factory, config, output, operation}", key, c.Role)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no pyotp contracts loaded; every assertion above passed vacuously")
	}
}

func TestPythonPyotpContract_LibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("python", "pyotp.yaml"))
	if err != nil {
		t.Fatalf("read pyotp.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(pyotp.yaml): %v", err)
	}
	if kb.Ecosystem != "python" || kb.SchemaVersion != "2" {
		t.Errorf("ecosystem/schema = %q/%q, want python/2", kb.Ecosystem, kb.SchemaVersion)
	}
	if kb.Library == nil || kb.Library.Name != pyotpLibrary {
		t.Fatalf("library block = %+v, want name pyotp", kb.Library)
	}
	if got := strings.Join(kb.Library.Coordinates, ","); got != "pyotp" {
		t.Errorf("library.coordinates = %q, want pyotp", got)
	}
	// generate_otp returned an int before 2.0 and a zero-padded str from 2.0
	// on, so the builtins.str returns above bound the range.
	if got := kb.Library.VersionRange; got != ">=2.0" {
		t.Errorf("library.version_range = %q, want >=2.0", got)
	}
}

// TestPythonPyotpContract_UncontractedAPIsAreAbsent pins the surface this
// family deliberately does not contract, with the reason, so adding one later
// reads as a scope decision being reversed.
func TestPythonPyotpContract_UncontractedAPIsAreAbsent(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	if got := kb.ContractsForTolerant("pyotp.totp.TOTP.now", 0); len(got) == 0 {
		t.Fatal("positive control failed: pyotp.totp.TOTP.now does not resolve, " +
			"so the negative assertions below prove nothing")
	}

	for _, absent := range []struct{ key, reason string }{
		{"pyotp.totp.TOTP.timecode", "time arithmetic on the interval; no cryptographic operation"},
		{"pyotp.otp.OTP.int_to_bytestring", "serializes the counter; no cryptographic operation"},
		{"pyotp.utils.build_uri", "helper behind provisioning_uri, not re-exported by the package"},
		{"pyotp.utils.strings_equal", "helper behind verify, not re-exported by the package"},
		{"pyotp.contrib.Steam", "no detection rule matches the Steam TOTP variant yet"},
		{"pyotp.contrib.steam.Steam", "no detection rule matches the Steam TOTP variant yet"},
	} {
		for _, arity := range []int{0, 1, 2, 3} {
			for _, c := range kb.ContractsForTolerant(absent.key, arity) {
				if c.SourceLibrary == pyotpLibrary {
					t.Errorf("%s resolves to a pyotp contract, but it is deliberately not contracted: %s",
						absent.key, absent.reason)
				}
			}
		}
	}
}
