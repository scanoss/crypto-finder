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

const paramikoLibrary = "paramiko"

// renderParamikoContract renders every field the loader parses, so a mutation
// to any of them changes the line. `Index` is a *int and `Contributes` is nil
// on a contribution-free parameter, so both are nil-guarded.
func renderParamikoContract(key string, c contracts.Contract) string {
	params := "-"
	if len(c.ParameterTypes) > 0 {
		params = strings.Join(c.ParameterTypes, "|")
	}
	when := "-"
	if c.When != nil {
		when = "conditional"
	}
	canonical := c.CanonicalReturnType
	if canonical == "" {
		canonical = "-"
	}
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
			rendered = append(rendered, fmt.Sprintf("%s:%s:%s:%s:%s",
				idx, p.Name, p.Role, property, derivation))
		}
		paramRoles = strings.Join(rendered, ",")
	}
	return fmt.Sprintf("%s %s/%s/%s/%s/%s/%s/params=%s/varargs=%t/when=%s/lib=%s",
		key, c.Method, c.Role, c.Return.Type, c.Return.Confidence,
		params, canonical, paramRoles, c.Varargs, when, c.SourceLibrary)
}

func loadedParamikoContracts(t *testing.T) []string {
	t.Helper()
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	var lines []string
	for key, list := range kb.Contracts {
		for i := range list {
			if list[i].SourceLibrary != paramikoLibrary {
				continue
			}
			lines = append(lines, renderParamikoContract(key, list[i]))
		}
	}
	if len(lines) == 0 {
		t.Fatal("no paramiko contracts loaded from the embedded python KB")
	}
	sort.Strings(lines)
	return lines
}

// pk renders one expected line. It only formats; every value passed to it
// below is written by hand from the paramiko sources.
func pk(method string, arity int, role, ret, paramRoles string) string {
	return fmt.Sprintf("%s#%d %s/%s/%s/high/-/-/params=%s/varargs=false/when=-/lib=paramiko",
		method, arity, method, role, ret, paramRoles)
}

const (
	rsaKey     = "paramiko.rsakey.RSAKey"
	dssKey     = "paramiko.dsskey.DSSKey"
	ecdsaKey   = "paramiko.ecdsakey.ECDSAKey"
	ed25519Key = "paramiko.ed25519key.Ed25519Key"
	pKey       = "paramiko.pkey.PKey"
	transport  = "paramiko.transport.Transport"
	sshClient  = "paramiko.client.SSHClient"
	hostKeys   = "paramiko.hostkeys.HostKeys"
	message    = "paramiko.message.Message"
	noneType   = "builtins.NoneType"
	bitsKey    = "0:bits:metadata-contributing:keySize:argument_value"
)

// constructorSpellings are the three keys a paramiko constructor is reached
// by, measured on an exported call graph: `paramiko.X(..)` emits the
// re-export attribute path, `from paramiko import X; X(..)` its `.<init>`,
// and `from paramiko.<module> import X; X(..)` the defining module's `.<init>`.
func constructorSpellings(reexport, defining string, arity int, ret string) []string {
	return []string{
		pk(reexport, arity, "factory", ret, "-"),
		pk(reexport+".<init>", arity, "factory", ret, "-"),
		pk(defining+".<init>", arity, "factory", ret, "-"),
	}
}

// classSpellings are the two keys a static or class method is reached by:
// `paramiko.X.m` (both `import paramiko` and `from paramiko import X`) and
// `paramiko.<module>.X.m`.
func classSpellings(reexport, defining, method string, arity int, ret, paramRoles string) []string {
	return []string{
		pk(reexport+"."+method, arity, "factory", ret, paramRoles),
		pk(defining+"."+method, arity, "factory", ret, paramRoles),
	}
}

// keyInstanceMethods are the per-key-class instance methods. The KB lookup is
// by exact FQN and does not walk the hierarchy (a probe scan keys
// `key.get_fingerprint()` on an RSAKey receiver as
// `paramiko.rsakey.RSAKey.get_fingerprint`), so inherited methods are
// expected on every concrete class a consumer holds.
func keyInstanceMethods(class, signParams string) []string {
	return []string{
		pk(class+".sign_ssh_data", 1, "operation", message, signParams),
		pk(class+".verify_ssh_sig", 2, "operation", "builtins.bool", "-"),
		pk(class+".get_fingerprint", 0, "operation", "builtins.bytes", "-"),
		pk(class+".write_private_key_file", 1, "output", noneType, "-"),
		pk(class+".write_private_key", 1, "output", noneType, "-"),
		pk(class+".load_certificate", 1, "config", noneType, "-"),
	}
}

// wantParamikoContracts is written BY HAND from the paramiko 3.5.1 sources
// (the tier0 source), with 2.0.0, 4.0.0 and 5.0.0 read for drift. It is never
// derived from the YAML: a derived expectation is green on a corrupted one.
func wantParamikoContracts() []string {
	var want []string
	add := func(lines ...string) { want = append(want, lines...) }

	// rsakey.py:49 __init__ (all optional); :179 generate(bits, ..);
	// pkey.py:415/:439 from_private_key_file/from_private_key return cls(..);
	// rsakey.py:122 sign_ssh_data(data, algorithm=None), `algorithm`
	// picks ssh-rsa / rsa-sha2-256 / rsa-sha2-512; :138 verify_ssh_sig.
	add(constructorSpellings("paramiko.RSAKey", rsaKey, 0, rsaKey)...)
	add(classSpellings("paramiko.RSAKey", rsaKey, "generate", 1, rsaKey, bitsKey)...)
	add(classSpellings("paramiko.RSAKey", rsaKey, "from_private_key_file", 1, rsaKey, "-")...)
	add(classSpellings("paramiko.RSAKey", rsaKey, "from_private_key", 1, rsaKey, "-")...)
	add(keyInstanceMethods(rsaKey, "1:algorithm:operation-determining:-:-")...)

	// dsskey.py:48 __init__; :202 generate(bits=1024, ..); :111 / :136.
	// Removed in 4.0.0.
	add(constructorSpellings("paramiko.DSSKey", dssKey, 0, dssKey)...)
	add(classSpellings("paramiko.DSSKey", dssKey, "generate", 0, dssKey, bitsKey)...)
	add(classSpellings("paramiko.DSSKey", dssKey, "from_private_key_file", 1, dssKey, "-")...)
	add(classSpellings("paramiko.DSSKey", dssKey, "from_private_key", 1, dssKey, "-")...)
	add(keyInstanceMethods(dssKey, "-")...)

	// ecdsakey.py:109 __init__; :263 generate(curve=SECP256R1(),
	// progress_func=None, bits=None); :220 / :230.
	add(constructorSpellings("paramiko.ECDSAKey", ecdsaKey, 0, ecdsaKey)...)
	add(classSpellings("paramiko.ECDSAKey", ecdsaKey, "generate", 0, ecdsaKey,
		"0:curve:operation-determining:-:-,2:bits:metadata-contributing:keySize:argument_value")...)
	add(classSpellings("paramiko.ECDSAKey", ecdsaKey, "from_private_key_file", 1, ecdsaKey, "-")...)
	add(classSpellings("paramiko.ECDSAKey", ecdsaKey, "from_private_key", 1, ecdsaKey, "-")...)
	add(keyInstanceMethods(ecdsaKey, "-")...)

	// ed25519key.py:44 __init__; :197 / :203. There is no generate().
	add(constructorSpellings("paramiko.Ed25519Key", ed25519Key, 0, ed25519Key)...)
	add(classSpellings("paramiko.Ed25519Key", ed25519Key, "from_private_key_file", 1, ed25519Key, "-")...)
	add(classSpellings("paramiko.Ed25519Key", ed25519Key, "from_private_key", 1, ed25519Key, "-")...)
	add(keyInstanceMethods(ed25519Key, "-")...)

	// pkey.py:415 / :439; :128 from_path(path, passphrase=None) and
	// :202 from_type_string(key_type, key_bytes) pick the class at runtime.
	add(classSpellings("paramiko.PKey", pKey, "from_private_key_file", 1, pKey, "-")...)
	add(classSpellings("paramiko.PKey", pKey, "from_private_key", 1, pKey, "-")...)
	add(classSpellings("paramiko.PKey", pKey, "from_path", 1, pKey, "-")...)
	add(classSpellings("paramiko.PKey", pKey, "from_type_string", 2, pKey,
		"0:key_type:operation-determining:-:-")...)
	add(keyInstanceMethods(pKey, "-")...)

	// agent.py:409 Agent(); :66 get_keys() returns a tuple of AgentKey;
	// :484 AgentKey.sign_ssh_data(data, algorithm=None).
	add(constructorSpellings("paramiko.Agent", "paramiko.agent.Agent", 0, "paramiko.agent.Agent")...)
	add(pk("paramiko.agent.Agent.get_keys", 0, "factory", "builtins.tuple", "-"))
	add(pk("paramiko.agent.AgentKey.sign_ssh_data", 1, "operation", message,
		"1:algorithm:operation-determining:-:-"))

	// transport.py:364 __init__(sock, ..); :679 get_security_options returns
	// SecurityOptions(self); :722 start_client; :780 start_server;
	// :1341 connect; :1236 renegotiate_keys; :1662 auth_publickey returns the
	// list of further auth types; :846 add_server_key; :866 get_server_key;
	// :939 get_remote_server_key; :888 @staticmethod load_server_moduli
	// returns True/False.
	add(constructorSpellings("paramiko.Transport", transport, 1, transport)...)
	add(pk(transport+".get_security_options", 0, "output", "paramiko.transport.SecurityOptions", "-"))
	add(pk(transport+".start_client", 0, "operation", noneType, "-"))
	add(pk(transport+".start_server", 0, "operation", noneType, "-"))
	add(pk(transport+".connect", 0, "operation", noneType, "-"))
	add(pk(transport+".renegotiate_keys", 0, "operation", noneType, "-"))
	add(pk(transport+".auth_publickey", 2, "operation", "builtins.list", "-"))
	add(pk(transport+".add_server_key", 1, "config", noneType, "-"))
	add(pk(transport+".get_server_key", 0, "output", pKey, "-"))
	add(pk(transport+".get_remote_server_key", 0, "output", pKey, "-"))
	add(pk("paramiko.Transport.load_server_moduli", 0, "config", "builtins.bool", "-"))
	add(pk(transport+".load_server_moduli", 0, "config", "builtins.bool", "-"))

	// client.py:68 __init__(); :80 load_system_host_keys; :109 load_host_keys;
	// :153 get_host_keys; :171 set_missing_host_key_policy(policy);
	// :217 connect(hostname, ..); :610 get_transport.
	add(constructorSpellings("paramiko.SSHClient", sshClient, 0, sshClient)...)
	add(pk(sshClient+".load_system_host_keys", 0, "config", noneType, "-"))
	add(pk(sshClient+".load_host_keys", 1, "config", noneType, "-"))
	add(pk(sshClient+".get_host_keys", 0, "output", hostKeys, "-"))
	add(pk(sshClient+".set_missing_host_key_policy", 1, "config", noneType,
		"0:policy:operation-determining:-:-"))
	add(pk(sshClient+".connect", 1, "operation", noneType, "-"))
	add(pk(sshClient+".get_transport", 0, "output", transport, "-"))

	// client.py:846 AutoAddPolicy, :864 RejectPolicy, :882 WarningPolicy.
	for _, policy := range []string{"AutoAddPolicy", "RejectPolicy", "WarningPolicy"} {
		add(constructorSpellings("paramiko."+policy, "paramiko.client."+policy, 0, "paramiko.client."+policy)...)
	}

	// hostkeys.py:47 __init__(filename=None); :74 load; :59 add(hostname,
	// keytype, key); :208 check(hostname, key); :285 @staticmethod
	// hash_host(hostname, salt=None), HMAC-SHA1.
	add(constructorSpellings("paramiko.HostKeys", hostKeys, 0, hostKeys)...)
	add(pk(hostKeys+".load", 1, "config", noneType, "-"))
	add(pk(hostKeys+".add", 3, "config", noneType, "-"))
	add(pk(hostKeys+".check", 2, "operation", "builtins.bool", "-"))
	add(pk("paramiko.HostKeys.hash_host", 1, "operation", "builtins.str", "-"))
	add(pk(hostKeys+".hash_host", 1, "operation", "builtins.str", "-"))

	// util.py:142 generate_key_bytes(hash_alg, salt, key, nbytes).
	add(pk("paramiko.util.generate_key_bytes", 4, "operation", "builtins.bytes",
		"0:hash_alg:operation-determining:-:-"))

	return want
}

func TestPythonParamikoContract_ExactSet(t *testing.T) {
	t.Parallel()

	want := wantParamikoContracts()
	sort.Strings(want)
	got := loadedParamikoContracts(t)

	wantSet := make(map[string]struct{}, len(want))
	for _, line := range want {
		if _, dup := wantSet[line]; dup {
			t.Errorf("expectation lists a line twice: %q", line)
		}
		wantSet[line] = struct{}{}
	}
	gotSet := make(map[string]struct{}, len(got))
	for _, line := range got {
		gotSet[line] = struct{}{}
	}

	for _, line := range want {
		if _, ok := gotSet[line]; !ok {
			t.Errorf("contract entry declared in the expectation but NOT loaded from the YAML:\n\t%q", line)
		}
	}
	for _, line := range got {
		if _, ok := wantSet[line]; !ok {
			t.Errorf("unexpected contract entry; if the YAML change is intended, add it to wantParamikoContracts():\n\t%q", line)
		}
	}
}

func TestPythonParamikoContract_RolesAreInTheAllowedVocabulary(t *testing.T) {
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
			if c.SourceLibrary != paramikoLibrary {
				continue
			}
			seen++
			if _, ok := allowed[c.Role]; !ok {
				t.Errorf("%s: role %q is not in {factory, config, output, operation}", key, c.Role)
			}
			if c.Role == "factory" && c.Return.Type == "" {
				t.Errorf("%s: role=factory with no return type cannot rekey a receiver", key)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no paramiko contracts loaded; every assertion above passed vacuously")
	}
}

func TestPythonParamikoContract_LibraryBlock(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("python", "paramiko.yaml"))
	if err != nil {
		t.Fatalf("read paramiko.yaml: %v", err)
	}
	kb, err := contracts.Load(data)
	if err != nil {
		t.Fatalf("Load(paramiko.yaml): %v", err)
	}
	if kb.Ecosystem != "python" || kb.SchemaVersion != "2" {
		t.Errorf("ecosystem/schema = %q/%q, want python/2", kb.Ecosystem, kb.SchemaVersion)
	}
	if kb.Library == nil {
		t.Fatal("library block absent")
	}
	if kb.Library.Name != paramikoLibrary {
		t.Errorf("library.name = %q, want paramiko", kb.Library.Name)
	}
	if got := strings.Join(kb.Library.Coordinates, ","); got != "paramiko" {
		t.Errorf("library.coordinates = %q, want paramiko", got)
	}
	// 2.x through 5.x: 1.x used PyCrypto and a different key API.
	if got, want := kb.Library.VersionRange, ">=2.0,<6.0"; got != want {
		t.Errorf("library.version_range = %q, want %q", got, want)
	}
}

// TestPythonParamikoContract_DocumentedIdiomRekeysTheReceiver pins the reason
// the re-export spellings exist: `key = paramiko.RSAKey.generate(bits=2048)`
// emits `paramiko.RSAKey.generate`, and only a contract under that key types
// `key` so that `key.sign_ssh_data(..)` lands on the library method.
func TestPythonParamikoContract_DocumentedIdiomRekeysTheReceiver(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	for _, tc := range []struct {
		factory string
		arity   int
		method  string
	}{
		{"paramiko.RSAKey.generate", 1, "sign_ssh_data"},
		{"paramiko.Ed25519Key", 1, "verify_ssh_sig"},
		{"paramiko.Transport", 1, "get_security_options"},
		{"paramiko.SSHClient.<init>", 0, "set_missing_host_key_policy"},
	} {
		factories := kb.ContractsForTolerant(tc.factory, tc.arity)
		if len(factories) != 1 {
			t.Errorf("%s#%d: got %d contracts, want exactly one", tc.factory, tc.arity, len(factories))
			continue
		}
		receiver := factories[0].Return.Type
		if methods := kb.ContractsForTolerant(receiver+"."+tc.method, 1); len(methods) == 0 {
			t.Errorf("%s types its receiver as %s, but %s.%s has no contract, so the call stays on the consumer's variable",
				tc.factory, receiver, receiver, tc.method)
		}
	}
}

// TestPythonParamikoContract_UncontractedAPIsAreAbsent pins the surface this
// family deliberately does not contract, each with its reason.
func TestPythonParamikoContract_UncontractedAPIsAreAbsent(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	if got := kb.ContractsFor("paramiko.RSAKey.generate", 1); len(got) == 0 {
		t.Fatal("positive control failed: paramiko.RSAKey.generate#1 does not resolve, " +
			"so the negative assertions below prove nothing")
	}

	for _, absent := range []struct{ key, reason string }{
		{"paramiko.ed25519key.Ed25519Key.generate", "no paramiko release defines it; the call raises AttributeError"},
		{"paramiko.Ed25519Key.generate", "no paramiko release defines it; the call raises AttributeError"},
		{"paramiko.client.SSHClient.open_sftp", "file transfer, not cryptography"},
		{"paramiko.client.SSHClient.exec_command", "channel I/O over an established session"},
		{"paramiko.transport.Transport.open_sftp_client", "file transfer, not cryptography"},
		{"paramiko.transport.Transport.auth_password", "sends a credential over the already-encrypted channel"},
		{"paramiko.sftp_client.SFTPClient.get", "file transfer, not cryptography"},
		{"paramiko.pkey.PKey.get_bits", "declared int return is already informative"},
		{"paramiko.client.MissingHostKeyPolicy.missing_host_key", "library-invoked callback; consumers override it"},
		{"paramiko.ServiceRequestingTransport", "needs-follow-up: auth_strategy path, 3.2.0+"},
		{"paramiko.OnDiskPrivateKey", "needs-follow-up: auth_strategy path, 3.2.0+"},
	} {
		for _, arity := range []int{0, 1, 2, 3} {
			for _, c := range kb.ContractsForTolerant(absent.key, arity) {
				if c.SourceLibrary == paramikoLibrary {
					t.Errorf("%s resolves to a paramiko contract, but it is deliberately not contracted: %s",
						absent.key, absent.reason)
				}
			}
		}
	}
}
