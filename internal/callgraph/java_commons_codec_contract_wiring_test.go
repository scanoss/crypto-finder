package callgraph

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

type codecWant struct {
	role    string
	library string
}

// resolveCodecCalls parses one Java source through the real parser and looks
// every call with a resolved owning type up in the embedded Java KB, keyed the
// way the engine keys it.
func resolveCodecCalls(t *testing.T, src string) map[string][]contracts.Contract {
	t.Helper()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "App.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewJavaParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	resolved := map[string][]contracts.Contract{}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			for j := range analysis.Functions[i].Calls {
				call := &analysis.Functions[i].Calls[j]
				callee := call.Callee
				name, _ := splitMethodArity(&callee)
				if callee.Package == "" || callee.Type == "" {
					continue
				}
				key := name + "#" + strconv.Itoa(len(call.Arguments))
				resolved[key] = append(resolved[key], kb.ContractsForTolerant(name, len(call.Arguments))...)
			}
		}
	}
	return resolved
}

func assertCodecResolution(t *testing.T, resolved map[string][]contracts.Contract, want map[string]codecWant) {
	t.Helper()
	for key, w := range want {
		got, ok := resolved[key]
		if !ok {
			t.Errorf("parsed calls did not cover %s", key)
			continue
		}
		if len(got) == 0 {
			t.Errorf("%s resolved to no contract", key)
			continue
		}
		for i := range got {
			c := &got[i]
			if c.Role != w.role {
				t.Errorf("%s: role = %q, want %q", key, c.Role, w.role)
			}
			if c.SourceLibrary != w.library {
				t.Errorf("%s: library = %q, want %q", key, c.SourceLibrary, w.library)
			}
		}
	}
}

// Digests and HMAC share one tracer: the static one-shots, the JCE factories
// they hand out, and the 1.11 instance API reached through a local variable and
// through a chained constructor.
func TestCommonsCodecDigestAndHmacContractsResolveParsedCalls(t *testing.T) {
	t.Parallel()

	resolved := resolveCodecCalls(t, `package app;

import java.security.MessageDigest;
import javax.crypto.Mac;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;

public class App {
    public String oneShot(byte[] data) {
        byte[] raw = DigestUtils.sha256(data);
        return DigestUtils.md5Hex(data) + DigestUtils.sha3_512Hex(raw);
    }

    public byte[] streaming(byte[] data) {
        MessageDigest md = DigestUtils.getSha512Digest();
        DigestUtils.updateDigest(md, data);
        return DigestUtils.digest(DigestUtils.getDigest("SHA-384"), data);
    }

    public String instance(byte[] data) {
        DigestUtils du = new DigestUtils("SHA-256");
        return du.digestAsHex(data);
    }

    public String hmacOneShot(byte[] key, byte[] data) {
        Mac mac = HmacUtils.getInitializedMac(HmacAlgorithms.HMAC_SHA_256, key);
        HmacUtils.updateHmac(mac, data);
        return HmacUtils.hmacSha1Hex(key, data);
    }

    public String hmacInstance(byte[] key, byte[] data) {
        return new HmacUtils(HmacAlgorithms.HMAC_SHA_512, key).hmacHex(data);
    }
}
`)

	const digest, hmac = "commons-codec-digestutils", "commons-codec-hmacutils"
	assertCodecResolution(t, resolved, map[string]codecWant{
		"org.apache.commons.codec.digest.DigestUtils.sha256#1":          {"operation", digest},
		"org.apache.commons.codec.digest.DigestUtils.md5Hex#1":          {"operation", digest},
		"org.apache.commons.codec.digest.DigestUtils.sha3_512Hex#1":     {"operation", digest},
		"org.apache.commons.codec.digest.DigestUtils.getSha512Digest#0": {"factory", digest},
		"org.apache.commons.codec.digest.DigestUtils.updateDigest#2":    {"operation", digest},
		"org.apache.commons.codec.digest.DigestUtils.digest#2":          {"operation", digest},
		"org.apache.commons.codec.digest.DigestUtils.getDigest#1":       {"factory", digest},
		"org.apache.commons.codec.digest.DigestUtils.<init>#1":          {"factory", digest},
		"org.apache.commons.codec.digest.DigestUtils.digestAsHex#1":     {"operation", digest},
		"org.apache.commons.codec.digest.HmacUtils.getInitializedMac#2": {"factory", hmac},
		"org.apache.commons.codec.digest.HmacUtils.updateHmac#2":        {"operation", hmac},
		"org.apache.commons.codec.digest.HmacUtils.hmacSha1Hex#2":       {"operation", hmac},
		"org.apache.commons.codec.digest.HmacUtils.<init>#2":            {"factory", hmac},
		"org.apache.commons.codec.digest.HmacUtils.hmacHex#1":           {"operation", hmac},
	})
}

func TestCommonsCodecPasswordCryptContractsResolveParsedCalls(t *testing.T) {
	t.Parallel()

	resolved := resolveCodecCalls(t, `package app;

import org.apache.commons.codec.digest.Crypt;
import org.apache.commons.codec.digest.Md5Crypt;
import org.apache.commons.codec.digest.Sha2Crypt;
import org.apache.commons.codec.digest.UnixCrypt;

public class App {
    public String[] hash(String password, byte[] raw, String salt) {
        return new String[] {
            Crypt.crypt(password),
            Crypt.crypt(password, salt),
            UnixCrypt.crypt(password, "ab"),
            Md5Crypt.md5Crypt(raw, salt),
            Md5Crypt.apr1Crypt(password),
            Sha2Crypt.sha256Crypt(raw),
            Sha2Crypt.sha512Crypt(raw, salt),
        };
    }
}
`)

	const lib = "commons-codec-crypt"
	assertCodecResolution(t, resolved, map[string]codecWant{
		"org.apache.commons.codec.digest.Crypt.crypt#1":           {"operation", lib},
		"org.apache.commons.codec.digest.UnixCrypt.crypt#2":       {"operation", lib},
		"org.apache.commons.codec.digest.Md5Crypt.md5Crypt#2":     {"operation", lib},
		"org.apache.commons.codec.digest.Md5Crypt.apr1Crypt#1":    {"operation", lib},
		"org.apache.commons.codec.digest.Sha2Crypt.sha256Crypt#1": {"operation", lib},
		"org.apache.commons.codec.digest.Sha2Crypt.sha512Crypt#2": {"operation", lib},
		"org.apache.commons.codec.digest.Crypt.crypt#2":           {"operation", lib},
	})
}

// The digest and crypt contracts sit in a separate file from the BLAKE3 ones
// under the same coordinates. This pins that the BLAKE3 lifecycle still resolves
// from its own library beside them.
func TestCommonsCodecBlake3ContractsStillResolveParsedCalls(t *testing.T) {
	t.Parallel()

	resolved := resolveCodecCalls(t, `package app;

import org.apache.commons.codec.digest.Blake3;

public class App {
    public byte[] hash(byte[] key, byte[] data) {
        byte[] out = new byte[32];
        Blake3 hasher = Blake3.initKeyedHash(key);
        hasher.update(data);
        hasher.doFinalize(out);
        return Blake3.hash(data);
    }
}
`)

	const lib = "commons-codec-blake3"
	assertCodecResolution(t, resolved, map[string]codecWant{
		"org.apache.commons.codec.digest.Blake3.initKeyedHash#1": {"factory", lib},
		"org.apache.commons.codec.digest.Blake3.update#1":        {"operation", lib},
		"org.apache.commons.codec.digest.Blake3.doFinalize#1":    {"operation", lib},
		"org.apache.commons.codec.digest.Blake3.hash#1":          {"factory", lib},
	})
}

// Most of Commons Codec is encoding, not cryptography. Base64, Hex, the binary
// and URL codecs and the phonetic encoders must parse to resolved calls yet
// resolve to no contract.
func TestCommonsCodecEncodingCallsResolveToNoContract(t *testing.T) {
	t.Parallel()

	resolved := resolveCodecCalls(t, `package app;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.BinaryCodec;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.language.Soundex;
import org.apache.commons.codec.net.URLCodec;

public class App {
    public String encode(byte[] raw, String name) throws Exception {
        String b64 = Base64.encodeBase64String(raw);
        byte[] back = Base64.decodeBase64(b64);
        String hex = Hex.encodeHexString(back);
        byte[] bits = BinaryCodec.toAsciiBytes(raw);
        String url = new URLCodec().encode(name);
        return b64 + hex + bits.length + url + new Soundex().soundex(name);
    }
}
`)

	encoding := []string{
		"org.apache.commons.codec.binary.Base64.encodeBase64String#1",
		"org.apache.commons.codec.binary.Base64.decodeBase64#1",
		"org.apache.commons.codec.binary.Hex.encodeHexString#1",
		"org.apache.commons.codec.binary.BinaryCodec.toAsciiBytes#1",
		"org.apache.commons.codec.net.URLCodec.encode#1",
		"org.apache.commons.codec.language.Soundex.soundex#1",
	}
	for _, key := range encoding {
		got, ok := resolved[key]
		if !ok {
			t.Errorf("parsed calls did not cover %s", key)
			continue
		}
		if len(got) != 0 {
			t.Errorf("%s resolved to %d contract(s), want none", key, len(got))
		}
	}
}

// The algorithm is chosen at the call site for the dispatching APIs, so the
// argument that chooses it has to be reported, and HMAC keys expose their size.
func TestCommonsCodecContractsReportAlgorithmAndKey(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	for _, tc := range []struct {
		method   string
		arity    int
		index    int
		role     string
		property string
	}{
		{"org.apache.commons.codec.digest.DigestUtils.getDigest", 1, 0, "operation-determining", "algorithm"},
		{"org.apache.commons.codec.digest.DigestUtils.<init>", 1, 0, "operation-determining", "algorithm"},
		{"org.apache.commons.codec.digest.HmacUtils.<init>", 2, 0, "operation-determining", "algorithm"},
		{"org.apache.commons.codec.digest.HmacUtils.<init>", 2, 1, "metadata-contributing", "keySize"},
		{"org.apache.commons.codec.digest.HmacUtils.getInitializedMac", 2, 0, "operation-determining", "algorithm"},
		{"org.apache.commons.codec.digest.HmacUtils.getInitializedMac", 2, 1, "metadata-contributing", "keySize"},
		{"org.apache.commons.codec.digest.HmacUtils.hmacSha256", 2, 0, "metadata-contributing", "keySize"},
		{"org.apache.commons.codec.digest.Crypt.crypt", 2, 1, "operation-determining", "algorithm"},
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
			if p.Role != tc.role || p.Contributes == nil || p.Contributes.Property != tc.property {
				t.Errorf("%s arity %d: parameters[%d] = %q %#v, want %q contributing %q",
					tc.method, tc.arity, tc.index, p.Role, p.Contributes, tc.role, tc.property)
			}
		}
		if !found {
			t.Errorf("%s arity %d: no parameter entry at index %d", tc.method, tc.arity, tc.index)
		}
	}
}
