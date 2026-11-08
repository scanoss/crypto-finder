// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
)

// materialFixture is one source file whose random draw (the `draw` text,
// which must occur once) a drbg rule reports.
type materialFixture struct {
	ecosystem  string
	file       string
	importPath string
	src        string
	draw       string
}

// materialsAtDraw scans the fixture's graph the way a scan with a call graph
// does and returns, sorted, the material types reported at the draw.
func materialsAtDraw(t *testing.T, fx materialFixture, existing ...entities.CryptographicAsset) []string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, fx.file)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(fx.src), 0o600); err != nil {
		t.Fatal(err)
	}
	var b *callgraph.Builder
	if fx.ecosystem == ecosystemJava {
		b = callgraph.NewBuilderForEcosystem(ecosystemJava, callgraph.NewJavaParser())
	} else {
		b = callgraph.NewBuilderForEcosystem(fx.ecosystem, callgraph.NewParserForEcosystem(fx.ecosystem))
		b.SetTypeResolver(callgraph.NewTypeResolverForEcosystem(fx.ecosystem, javaruntime.Config{}))
	}
	graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: fx.importPath}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	if strings.Count(fx.src, fx.draw) != 1 {
		t.Fatalf("draw %q must occur once in the fixture", fx.draw)
	}
	line, col := 1, 0
	for i, text := range strings.Split(fx.src, "\n") {
		if c := strings.Index(text, fx.draw); c >= 0 {
			line, col = i+1, c+1
			break
		}
	}
	draw := entities.CryptographicAsset{
		StartLine: line, EndLine: line, StartCol: col, EndCol: col + len(fx.draw),
		Match:    fx.draw,
		Rules:    []entities.RuleInfo{{ID: "test.crypto.random.drbg"}},
		Metadata: map[string]string{"assetType": "algorithm", "algorithmPrimitive": "drbg", "algorithmName": "CSPRNG"},
	}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath:            path,
		Language:            fx.ecosystem,
		CryptographicAssets: append([]entities.CryptographicAsset{draw}, existing...),
	}}}
	MaterializeRelatedMaterial(report, &engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, Ecosystem: fx.ecosystem,
	})
	var got []string
	assets := report.Findings[0].CryptographicAssets
	for i := range assets {
		a := &assets[i]
		if a.Metadata["assetType"] != "related-crypto-material" {
			continue
		}
		if a.StartLine != line || a.StartCol != col || len(a.Rules) != 1 || a.Rules[0].ID != draw.Rules[0].ID {
			t.Errorf("material %+v is not at the draw %d:%d with the draw's rule", a, line, col)
		}
		got = append(got, a.Metadata["materialType"])
	}
	slices.Sort(got)
	return got
}

const pythonKdfHeader = `import os
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return kdf.derive(password)


def log_value(value):
    print(value)
`

func TestMaterializeRelatedMaterial(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		fx   materialFixture
		want []string
	}{
		"python salt drawn in caller, consumed in helper": {
			fx: materialFixture{ecosystem: ecosystemPython, file: "app/kdf.py", importPath: "app", draw: "os.urandom(16)", src: pythonKdfHeader + `

def main(password):
    salt = os.urandom(16)
    return derive(password, salt)
`},
			want: []string{"salt"},
		},
		"python keyword argument into helper": {
			fx: materialFixture{ecosystem: ecosystemPython, file: "app/kdf.py", importPath: "app", draw: "secrets.token_bytes(16)", src: pythonKdfHeader + `

def main(password):
    salt = secrets.token_bytes(16)
    return derive(password, salt=salt)
`},
			want: []string{"salt"},
		},
		"python iv through a method": {
			fx: materialFixture{ecosystem: ecosystemPython, file: "app/box.py", importPath: "app", draw: "os.urandom(16)", src: pythonKdfHeader + `

class Box:
    def seal(self, key, iv, data):
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return encryptor.update(data)


def run(key, data):
    box = Box()
    iv = os.urandom(16)
    return box.seal(key, iv, data)
`},
			want: []string{"initialization-vector"},
		},
		"python drawn value written as the argument": {
			fx: materialFixture{ecosystem: ecosystemPython, file: "app/kdf.py", importPath: "app", draw: "os.urandom(16)", src: pythonKdfHeader + `

def main(password):
    return derive(password, os.urandom(16))
`},
			want: []string{"salt"},
		},
		"python three helpers deep": {
			fx: materialFixture{ecosystem: ecosystemPython, file: "app/kdf.py", importPath: "app", draw: "os.urandom(16)", src: pythonKdfHeader + `

def hop2(password, salt):
    return derive(password, salt)


def hop1(password, salt):
    return hop2(password, salt)


def main(password):
    salt = os.urandom(16)
    return hop1(password, salt)
`},
			want: []string{"salt"},
		},
		"python value reassigned before passing": {
			fx: materialFixture{ecosystem: ecosystemPython, file: "app/kdf.py", importPath: "app", draw: "os.urandom(16)", src: pythonKdfHeader + `

def main(password):
    salt = os.urandom(16)
    salt = b"fixed-salt-value"
    return derive(password, salt)
`},
		},
		"python parameter reassigned in the helper": {
			fx: materialFixture{ecosystem: ecosystemPython, file: "app/kdf.py", importPath: "app", draw: "os.urandom(16)", src: pythonKdfHeader + `

def derive_fixed(password, salt):
    salt = b"fixed-salt-value"
    return derive(password, salt)


def main(password):
    salt = os.urandom(16)
    return derive_fixed(password, salt)
`},
		},
		"python passed to a non-crypto callee": {
			fx: materialFixture{ecosystem: ecosystemPython, file: "app/kdf.py", importPath: "app", draw: "os.urandom(16)", src: pythonKdfHeader + `

def main(password):
    salt = os.urandom(16)
    log_value(salt)
    print(salt)
`},
		},
		"python depth exceeded": {
			fx: materialFixture{ecosystem: ecosystemPython, file: "app/kdf.py", importPath: "app", draw: "os.urandom(16)", src: pythonKdfHeader + `

def hop3(password, salt):
    return derive(password, salt)


def hop2(password, salt):
    return hop3(password, salt)


def hop1(password, salt):
    return hop2(password, salt)


def main(password):
    salt = os.urandom(16)
    return hop1(password, salt)
`},
		},
		"python unresolved callee": {
			fx: materialFixture{ecosystem: ecosystemPython, file: "app/kdf.py", importPath: "app", draw: "os.urandom(16)", src: pythonKdfHeader + `

def main(password, helper):
    salt = os.urandom(16)
    return helper.derive(password, salt)
`},
		},
		"go nonce through a helper into AEAD.Seal": {
			fx:   materialFixture{ecosystem: ecosystemGo, file: "a.go", importPath: "example.com/app", draw: "rand.Read(nonce)", src: goMaterialSource},
			want: []string{"nonce"},
		},
		"go iv filled by io.ReadFull into a CBC helper": {
			fx:   materialFixture{ecosystem: ecosystemGo, file: "a.go", importPath: "example.com/app", draw: "io.ReadFull(rand.Reader, iv)", src: goMaterialSource},
			want: []string{"initialization-vector"},
		},
		"go salt overwritten by copy before passing": {
			fx: materialFixture{ecosystem: ecosystemGo, file: "a.go", importPath: "example.com/app", draw: "rand.Read(salt)", src: goMaterialSource},
		},
		"java iv and salt through private helpers": {
			fx:   materialFixture{ecosystem: ecosystemJava, file: "app/A.java", importPath: "app", draw: "random.nextBytes(iv)", src: javaMaterialSource},
			want: []string{"initialization-vector"},
		},
		"java salt through this-qualified helper": {
			fx:   materialFixture{ecosystem: ecosystemJava, file: "app/A.java", importPath: "app", draw: "random.nextBytes(salt)", src: javaMaterialSource},
			want: []string{"salt"},
		},
		"java seed input is not the drawn value": {
			fx: materialFixture{ecosystem: ecosystemJava, file: "app/A.java", importPath: "app", draw: "random.setSeed(salt)", src: javaMaterialSource},
		},
		"rust declaration that only reads the buffer": {
			fx:   materialFixture{ecosystem: ecosystemRust, file: "src/lib.rs", importPath: "app", draw: "rand::rngs::OsRng.fill_bytes(&mut nonce)", src: rustMaterialSource},
			want: []string{"initialization-vector"},
		},
		"node declaration that only reads the value": {
			fx:   materialFixture{ecosystem: ecosystemNode, file: "a.js", importPath: "app", draw: "crypto.randomBytes(IV_LENGTH)", src: nodeMaterialSource},
			want: []string{"initialization-vector"},
		},
		"java buffer reassigned before passing": {
			fx: materialFixture{ecosystem: ecosystemJava, file: "app/A.java", importPath: "app", draw: "random.nextBytes(spare)", src: javaMaterialSource},
		},
		"rust iv through a helper into openssl encrypt": {
			fx:   materialFixture{ecosystem: ecosystemRust, file: "src/lib.rs", importPath: "app", draw: "rand::thread_rng().fill_bytes(&mut iv)", src: rustMaterialSource},
			want: []string{"initialization-vector"},
		},
		"rust salt through a helper into pbkdf2_hmac": {
			fx:   materialFixture{ecosystem: ecosystemRust, file: "src/lib.rs", importPath: "app", draw: "OsRng.fill_bytes(&mut salt)", src: rustMaterialSource},
			want: []string{"salt"},
		},
		"node iv and salt through helpers": {
			fx:   materialFixture{ecosystem: ecosystemNode, file: "a.js", importPath: "app", draw: "crypto.randomBytes(16)", src: nodeMaterialSource},
			want: []string{"initialization-vector"},
		},
		"node salt through a helper into pbkdf2Sync": {
			fx:   materialFixture{ecosystem: ecosystemNode, file: "a.js", importPath: "app", draw: "crypto.randomBytes(32)", src: nodeMaterialSource},
			want: []string{"salt"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := materialsAtDraw(t, tc.fx); !slices.Equal(got, tc.want) {
				t.Errorf("materials at the draw = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMaterializeRelatedMaterial_KeepsSameFunctionMaterial: a rule that saw
// draw and consumer in one function already reported the material at the
// draw, so the engine adds no second asset.
func TestMaterializeRelatedMaterial_KeepsSameFunctionMaterial(t *testing.T) {
	t.Parallel()

	fx := materialFixture{ecosystem: ecosystemPython, file: "app/kdf.py", importPath: "app", draw: "os.urandom(16)", src: pythonKdfHeader + `

def main(password):
    salt = os.urandom(16)
    return derive(password, salt)
`}
	at := strings.Index(fx.src, fx.draw)
	if at < 0 {
		t.Fatal("draw not in the fixture")
	}
	line := strings.Count(fx.src[:at], "\n") + 1
	col := strings.Index(strings.Split(fx.src, "\n")[line-1], fx.draw) + 1
	ruleMaterial := entities.CryptographicAsset{
		StartLine: line, EndLine: line, StartCol: col, EndCol: col + len(fx.draw),
		Rules:    []entities.RuleInfo{{ID: "test.crypto.random.drbg"}},
		Metadata: map[string]string{"assetType": "related-crypto-material", "materialType": "salt"},
	}
	if got := materialsAtDraw(t, fx, ruleMaterial); !slices.Equal(got, []string{"salt"}) {
		t.Errorf("materials at the draw = %q, want the rule's one salt", got)
	}
}

const goMaterialSource = `package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"golang.org/x/crypto/scrypt"
)

func seal(key, nonce, pt []byte) []byte {
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return aead.Seal(nil, nonce, pt, nil)
}

func cbc(key, iv, pt []byte) {
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(pt, pt)
}

func derive(pw, salt []byte) ([]byte, error) {
	return scrypt.Key(pw, salt, 32768, 8, 1, 32)
}

func Encrypt(key, pt []byte) []byte {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return seal(key, nonce, pt)
}

func EncryptCBC(key, pt []byte) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	cbc(key, iv, pt)
}

func Derive(pw, fixed []byte) {
	salt := make([]byte, 16)
	rand.Read(salt)
	copy(salt, fixed)
	derive(pw, salt)
}
`

const javaMaterialSource = `package app;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class A {
    private Cipher init(byte[] key, byte[] iv) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return c;
    }

    private PBEKeySpec spec(char[] pw, byte[] salt) {
        return new PBEKeySpec(pw, salt, 210000, 256);
    }

    public void run(byte[] key, char[] pw) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        init(key, iv);
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        this.spec(pw, salt);
        byte[] spare = new byte[16];
        random.nextBytes(spare);
        spare = key;
        init(key, spare);
    }

    public void seeded(char[] pw, byte[] salt) {
        SecureRandom random = new SecureRandom();
        random.setSeed(salt);
        this.spec(pw, salt);
    }
}
`

const rustMaterialSource = `use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::symm::{encrypt, Cipher};
use rand::rngs::OsRng;
use rand::RngCore;

fn enc(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    encrypt(Cipher::aes_128_cbc(), key, Some(iv), data).unwrap()
}

fn derive(pw: &[u8], salt: &[u8], out: &mut [u8]) {
    pbkdf2_hmac(pw, salt, 210000, MessageDigest::sha256(), out).unwrap();
}

pub fn run(key: &[u8], data: &[u8]) {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);
    enc(key, &iv, data);
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut out = [0u8; 32];
    derive(key, &salt, &mut out);
}

pub fn run_measured(key: &[u8], data: &[u8]) -> usize {
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let size = nonce.len();
    enc(key, &nonce, data);
    size
}
`

const nodeMaterialSource = `const crypto = require('crypto');

function enc(key, iv, data) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return cipher.update(data);
}

function derive(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 210000, 32, 'sha256');
}

function run(key, data) {
  const iv = crypto.randomBytes(16);
  enc(key, iv, data);
  const salt = crypto.randomBytes(32);
  derive(data, salt);
}

function runLogged(key, data) {
  const nonce = crypto.randomBytes(IV_LENGTH);
  const nonceHex = nonce.toString('hex');
  console.log(nonceHex);
  return enc(key, nonce, data);
}

const IV_LENGTH = 16;

module.exports = { run, runLogged };
`
