package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// sshdParsedRoles parses each Java source, looks up every call the parser
// resolved to a package and type, and returns the role of the single
// apache-sshd contract it keys on. A call that resolves to no contract maps to
// "", so absence is observable; a call keyed on another library, or on more
// than one contract, fails the test.
func sshdParsedRoles(t *testing.T, sources map[string]string) map[sshdCall]string {
	t.Helper()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}
	dir := t.TempDir()
	for name, src := range sources {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	analyses, err := NewJavaParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	got := map[sshdCall]string{}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			fn := &analysis.Functions[i]
			for j := range fn.Calls {
				call := &fn.Calls[j]
				callee := call.Callee
				name, _ := splitMethodArity(&callee)
				if callee.Package == "" || callee.Type == "" {
					continue
				}
				key := sshdCall{name, len(call.Arguments)}
				matches := kb.ContractsForTolerant(name, key.arity)
				switch {
				case len(matches) == 0:
					got[key] = ""
				case len(matches) > 1:
					t.Fatalf("%s#%d resolved to %d contracts, want one", name, key.arity, len(matches))
				case matches[0].SourceLibrary != "apache-sshd":
					continue
				default:
					got[key] = matches[0].Role
				}
			}
		}
	}
	return got
}

type sshdCall struct {
	method string
	arity  int
}

func assertSshdRoles(t *testing.T, got, want map[sshdCall]string) {
	t.Helper()
	for call, role := range want {
		gotRole, parsed := got[call]
		if !parsed {
			t.Errorf("parsed calls did not include %s#%d", call.method, call.arity)
			continue
		}
		if gotRole != role {
			t.Errorf("%s#%d: role = %q, want %q", call.method, call.arity, gotRole, role)
		}
	}
}

// A 2.x consumer: server and client setup with explicit algorithm lists, key
// loading, a client identity, and the cipher, MAC and signature lifecycles
// written against the SessionContext spelling. Starting, connecting and
// password identities are session plumbing rather than crypto and must stay
// uncategorized.
func TestApacheSshdContractsResolveParsedCallRoles(t *testing.T) {
	t.Parallel()

	got := sshdParsedRoles(t, map[string]string{"App.java": `package app;

import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.Collections;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.mac.BuiltinMacs;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;

public class App {
    public void server() throws Exception {
        SshServer sshd = SshServer.setUpDefaultServer();
        SimpleGeneratorHostKeyProvider hostKeys = new SimpleGeneratorHostKeyProvider(Paths.get("hostkey.ser"));
        hostKeys.setAlgorithm("EC");
        hostKeys.setKeySize(256);
        sshd.setKeyPairProvider(hostKeys);
        sshd.setCipherFactories(Collections.singletonList(BuiltinCiphers.aes256ctr));
        sshd.setMacFactories(Collections.singletonList(BuiltinMacs.hmacsha256));
        sshd.setSignatureFactories(Collections.singletonList(BuiltinSignatures.ed25519));
        sshd.setPort(2222);
        sshd.start();
    }

    public void client() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.setCipherFactoriesNames("aes128-ctr");
        client.start();
        ClientSession session = client.connect("u", "h", 22).verify().getSession();
        FileKeyPairProvider provider = new FileKeyPairProvider(Paths.get("id_ed25519"));
        for (KeyPair kp : provider.loadKeys(null)) {
            session.addPublicKeyIdentity(kp);
        }
        session.addPasswordIdentity("secret");
        SecurityUtils.loadKeyPairIdentities(null, null, null, null);
    }

    public byte[] primitives(byte[] key, byte[] iv, byte[] data) throws Exception {
        KeyPair kp = KeyUtils.generateKeyPair("ssh-rsa", 3072);
        String fp = KeyUtils.getFingerPrint(kp.getPublic());
        Cipher cipher = BuiltinCiphers.fromFactoryName("aes128-ctr").create();
        cipher.init(Cipher.Mode.Encrypt, key, iv);
        cipher.update(data, 0, data.length);
        Mac mac = BuiltinMacs.fromFactoryName("hmac-sha2-256").create();
        mac.init(key);
        mac.update(data);
        byte[] tag = mac.doFinal();
        Signature signer = BuiltinSignatures.fromFactoryName("ssh-ed25519").create();
        signer.initSigner(null, kp.getPrivate());
        signer.update(null, data);
        byte[] sig = signer.sign(null);
        javax.crypto.Cipher jce = SecurityUtils.getCipher("AES/CTR/NoPadding");
        return signer.verify(null, sig) ? sig : tag;
    }
}
`})

	assertSshdRoles(t, got, map[sshdCall]string{
		{"org.apache.sshd.server.SshServer.setUpDefaultServer", 0}:                            "factory",
		{"org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider.<init>", 1}:       "factory",
		{"org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider.setAlgorithm", 1}: "config",
		{"org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider.setKeySize", 1}:   "config",
		{"org.apache.sshd.server.SshServer.setKeyPairProvider", 1}:                            "config",
		{"org.apache.sshd.server.SshServer.setCipherFactories", 1}:                            "config",
		{"org.apache.sshd.server.SshServer.setMacFactories", 1}:                               "config",
		{"org.apache.sshd.server.SshServer.setSignatureFactories", 1}:                         "config",
		{"org.apache.sshd.server.SshServer.setPort", 1}:                                       "",
		{"org.apache.sshd.server.SshServer.start", 0}:                                         "",
		{"org.apache.sshd.client.SshClient.setUpDefaultClient", 0}:                            "factory",
		{"org.apache.sshd.client.SshClient.setCipherFactoriesNames", 1}:                       "config",
		{"org.apache.sshd.client.SshClient.start", 0}:                                         "",
		{"org.apache.sshd.client.SshClient.connect", 3}:                                       "",
		{"org.apache.sshd.common.keyprovider.FileKeyPairProvider.<init>", 1}:                  "factory",
		{"org.apache.sshd.common.keyprovider.FileKeyPairProvider.loadKeys", 1}:                "factory",
		{"org.apache.sshd.client.session.ClientSession.addPublicKeyIdentity", 1}:              "config",
		{"org.apache.sshd.client.session.ClientSession.addPasswordIdentity", 1}:               "",
		{"org.apache.sshd.common.util.security.SecurityUtils.loadKeyPairIdentities", 4}:       "factory",
		{"org.apache.sshd.common.config.keys.KeyUtils.generateKeyPair", 2}:                    "factory",
		{"org.apache.sshd.common.config.keys.KeyUtils.getFingerPrint", 1}:                     "operation",
		{"org.apache.sshd.common.cipher.BuiltinCiphers.fromFactoryName", 1}:                   "factory",
		{"org.apache.sshd.common.cipher.Cipher.init", 3}:                                      "config",
		{"org.apache.sshd.common.cipher.Cipher.update", 3}:                                    "operation",
		{"org.apache.sshd.common.mac.BuiltinMacs.fromFactoryName", 1}:                         "factory",
		{"org.apache.sshd.common.mac.Mac.init", 1}:                                            "config",
		{"org.apache.sshd.common.mac.Mac.update", 1}:                                          "operation",
		{"org.apache.sshd.common.mac.Mac.doFinal", 0}:                                         "operation",
		{"org.apache.sshd.common.signature.BuiltinSignatures.fromFactoryName", 1}:             "factory",
		{"org.apache.sshd.common.signature.Signature.initSigner", 2}:                          "config",
		{"org.apache.sshd.common.signature.Signature.update", 2}:                              "operation",
		{"org.apache.sshd.common.signature.Signature.sign", 1}:                                "operation",
		{"org.apache.sshd.common.signature.Signature.verify", 2}:                              "operation",
		{"org.apache.sshd.common.util.security.SecurityUtils.getCipher", 1}:                   "factory",
	})
}

// The covered range spans two package layouts and a signature change. A 1.x
// consumer signs without a SessionContext, and a 0.x consumer reaches the
// primitives and the client/server from their pre-1.0 packages. Each spelling
// must resolve, or a pinned older release reads as uncovered.
func TestApacheSshdContractsResolveLegacySpellings(t *testing.T) {
	t.Parallel()

	got := sshdParsedRoles(t, map[string]string{
		"V1.java": `package app;

import java.security.KeyPair;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.SecurityUtils;

public class V1 {
    public byte[] sign(Signature signer, Signature verifier, KeyPairProvider keys, byte[] data) throws Exception {
        for (KeyPair kp : keys.loadKeys()) {
            signer.initSigner(kp.getPrivate());
            signer.update(data);
            byte[] sig = signer.sign();
            verifier.initVerifier(kp.getPublic());
            verifier.update(data, 0, data.length);
            if (verifier.verify(sig)) {
                return sig;
            }
        }
        return SecurityUtils.getMessageDigest("SHA-256").digest(data);
    }
}
`,
		"V0.java": `package app;

import java.security.KeyPair;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.Cipher;
import org.apache.sshd.common.Mac;
import org.apache.sshd.common.Signature;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;

public class V0 {
    public void setup(ClientSession session, KeyPair kp) throws Exception {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider("hostkey.ser", "RSA", 2048));
        SshClient client = SshClient.setUpDefaultClient();
        client.setCipherFactories(null);
        session.addPublicKeyIdentity(kp);
    }

    public byte[] primitives(Cipher cipher, Mac mac, Signature sig, KeyPair kp, byte[] key, byte[] iv, byte[] data, byte[] out) throws Exception {
        cipher.init(Cipher.Mode.Decrypt, key, iv);
        cipher.update(data, 0, data.length);
        mac.init(key);
        mac.update(data, 0, data.length);
        mac.doFinal(out, 0);
        sig.init(kp.getPublic(), kp.getPrivate());
        sig.update(data, 0, data.length);
        return sig.verify(out) ? sig.sign() : out;
    }
}
`,
	})

	assertSshdRoles(t, got, map[sshdCall]string{
		{"org.apache.sshd.common.keyprovider.KeyPairProvider.loadKeys", 0}:              "factory",
		{"org.apache.sshd.common.signature.Signature.initSigner", 1}:                    "config",
		{"org.apache.sshd.common.signature.Signature.update", 1}:                        "operation",
		{"org.apache.sshd.common.signature.Signature.sign", 0}:                          "operation",
		{"org.apache.sshd.common.signature.Signature.initVerifier", 1}:                  "config",
		{"org.apache.sshd.common.signature.Signature.update", 3}:                        "operation",
		{"org.apache.sshd.common.signature.Signature.verify", 1}:                        "operation",
		{"org.apache.sshd.common.util.SecurityUtils.getMessageDigest", 1}:               "factory",
		{"org.apache.sshd.SshServer.setUpDefaultServer", 0}:                             "factory",
		{"org.apache.sshd.SshServer.setKeyPairProvider", 1}:                             "config",
		{"org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider.<init>", 3}: "factory",
		{"org.apache.sshd.SshClient.setUpDefaultClient", 0}:                             "factory",
		{"org.apache.sshd.SshClient.setCipherFactories", 1}:                             "config",
		{"org.apache.sshd.ClientSession.addPublicKeyIdentity", 1}:                       "config",
		{"org.apache.sshd.common.Cipher.init", 3}:                                       "config",
		{"org.apache.sshd.common.Cipher.update", 3}:                                     "operation",
		{"org.apache.sshd.common.Mac.init", 1}:                                          "config",
		{"org.apache.sshd.common.Mac.update", 3}:                                        "operation",
		{"org.apache.sshd.common.Mac.doFinal", 2}:                                       "operation",
		{"org.apache.sshd.common.Signature.init", 2}:                                    "config",
		{"org.apache.sshd.common.Signature.update", 3}:                                  "operation",
		{"org.apache.sshd.common.Signature.verify", 1}:                                  "operation",
		{"org.apache.sshd.common.Signature.sign", 0}:                                    "operation",
	})
}

// The algorithm an SSH consumer picks is a name string at the call site, and
// the key a primitive is initialized with is the only evidence of its size, so
// both have to be reported rather than left opaque.
func TestApacheSshdContractsReportAlgorithmAndKeySize(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	for _, tc := range []struct {
		method     string
		arity      int
		index      int
		role       string
		property   string
		derivation string
	}{
		{"org.apache.sshd.common.config.keys.KeyUtils.generateKeyPair", 2, 0, "operation-determining", "algorithm", "argument_value"},
		{"org.apache.sshd.common.config.keys.KeyUtils.generateKeyPair", 2, 1, "metadata-contributing", "keySize", "argument_value"},
		{"org.apache.sshd.common.cipher.BuiltinCiphers.fromFactoryName", 1, 0, "operation-determining", "algorithm", "argument_value"},
		{"org.apache.sshd.common.signature.BuiltinSignatures.fromFactoryName", 1, 0, "operation-determining", "algorithm", "argument_value"},
		{"org.apache.sshd.client.SshClient.setCipherFactoriesNames", 1, 0, "operation-determining", "algorithm", "argument_value"},
		{"org.apache.sshd.common.util.security.SecurityUtils.getSignature", 1, 0, "operation-determining", "algorithm", "argument_value"},
		{"org.apache.sshd.common.cipher.Cipher.init", 3, 1, "metadata-contributing", "keySize", "argument_bit_length"},
		{"org.apache.sshd.common.mac.Mac.init", 1, 0, "metadata-contributing", "keySize", "argument_bit_length"},
		{"org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider.<init>", 3, 2, "metadata-contributing", "keySize", "argument_value"},
	} {
		got := kb.ContractsForTolerant(tc.method, tc.arity)
		if len(got) != 1 {
			t.Errorf("ContractsForTolerant(%q, %d) = %d, want exactly one", tc.method, tc.arity, len(got))
			continue
		}
		var found bool
		for _, p := range got[0].Parameters {
			if p.Index == nil || *p.Index != tc.index {
				continue
			}
			found = true
			if p.Role != tc.role || p.Contributes == nil ||
				p.Contributes.Property != tc.property || p.Contributes.Derivation != tc.derivation {
				t.Errorf("%s#%d parameters[%d] = %s %#v, want %s %s/%s",
					tc.method, tc.arity, tc.index, p.Role, p.Contributes, tc.role, tc.property, tc.derivation)
			}
		}
		if !found {
			t.Errorf("%s#%d: no parameter entry at index %d", tc.method, tc.arity, tc.index)
		}
	}
}
