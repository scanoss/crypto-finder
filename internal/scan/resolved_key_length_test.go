// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
)

func TestResolvedKeyLengthFromContract(t *testing.T) {
	t.Parallel()

	ctx := newExportBuildContext(&engine.DepScanResult{
		CallGraph: &callgraph.CallGraph{},
		Ecosystem: "java",
	})
	keyGeneratorInit := callgraph.FunctionID{Package: "javax.crypto", Type: "KeyGenerator", Name: "init#1"}

	tests := []struct {
		name           string
		argument       string
		resolvedValue  string
		parameterType  string
		wantBits       int
		wantProvenance string
		wantAbsent     bool
	}{
		{
			name:           "literal key bits",
			argument:       "256",
			resolvedValue:  "256",
			parameterType:  "int",
			wantBits:       256,
			wantProvenance: "constant",
		},
		{
			name:           "ambiguous variable remains unresolved",
			argument:       "keyBits",
			parameterType:  "int",
			wantProvenance: "unknown",
		},
		{
			name:          "same arity non-int overload is excluded",
			argument:      "parameters",
			parameterType: "java.security.spec.AlgorithmParameterSpec",
			wantAbsent:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &callgraph.FunctionCall{
				Callee:    keyGeneratorInit,
				FilePath:  "KeyFlow.java",
				Line:      5,
				Arguments: []string{tt.argument},
			}
			parameters := []callGraphParameter{{
				ParameterIndex:     0,
				ArgumentExpression: tt.argument,
				ResolvedValue:      tt.resolvedValue,
			}}
			matches := contractMatchesForCall(ctx, call, len(call.Arguments))
			got := resolvedKeyLengthFromContract(ctx, matches, call, parameters, []string{tt.parameterType})
			if tt.wantAbsent {
				if got != nil {
					t.Fatalf("resolved key length = %#v, want nil for non-int overload", got)
				}
				return
			}
			if got == nil {
				t.Fatal("resolved key length = nil, want contract-scoped evidence")
			}
			if got.Provenance != tt.wantProvenance {
				t.Fatalf("provenance = %q, want %q", got.Provenance, tt.wantProvenance)
			}
			if got.SourceCall.FunctionName != "javax.crypto.KeyGenerator.init" || got.SourceCall.Line != call.Line || got.SourceCall.ParameterIndex != 0 {
				t.Fatalf("source_call = %#v, want init line %d parameter 0", got.SourceCall, call.Line)
			}
			if tt.wantProvenance == "constant" {
				if got.Bits == nil || *got.Bits != tt.wantBits {
					t.Fatalf("bits = %#v, want %d", got.Bits, tt.wantBits)
				}
			} else if got.Bits != nil {
				t.Fatalf("bits = %#v, want nil for unresolved input", got.Bits)
			}
		})
	}
}

// pythonKDFCall builds a synthetic hashlib.pbkdf2_hmac(hash_name, password,
// salt, iterations, <dklen-arg>) call for the row-C Python KDF tests
// (python-parser-parity-2): a fixed arity-5 shape with only the dklen
// argument (index 4) varying per test.
func pythonKDFCall(dklenArg, dklenResolvedValue string) (*callgraph.FunctionCall, []callGraphParameter) {
	call := &callgraph.FunctionCall{
		Callee:    callgraph.FunctionID{Package: "hashlib", Name: "pbkdf2_hmac"},
		FilePath:  "derive.py",
		Line:      7,
		Arguments: []string{"'sha256'", "password", "salt", "100000", dklenArg},
	}
	parameters := []callGraphParameter{
		{ParameterIndex: 0, ArgumentExpression: "'sha256'"},
		{ParameterIndex: 1, ArgumentExpression: "password"},
		{ParameterIndex: 2, ArgumentExpression: "salt"},
		{ParameterIndex: 3, ArgumentExpression: "100000"},
		{ParameterIndex: 4, ArgumentExpression: dklenArg, ResolvedValue: dklenResolvedValue},
	}
	return call, parameters
}

// TestResolvedKeyLength_Python_KeywordDklen (row C §5.2 step 3a,
// python-parser-parity-2) pins that a keyword `dklen=32` argument resolves
// via keyword-name matching, bypassing contractParameterTypesMatch (no
// parameterTypes evidence is supplied at all).
func TestResolvedKeyLength_Python_KeywordDklen(t *testing.T) {
	t.Parallel()

	ctx := newExportBuildContext(&engine.DepScanResult{
		CallGraph: &callgraph.CallGraph{},
		Ecosystem: "python",
	})
	call, parameters := pythonKDFCall("dklen=32", "32")
	matches := contractMatchesForCall(ctx, call, len(call.Arguments))
	got := resolvedKeyLengthFromContract(ctx, matches, call, parameters, nil)
	if got == nil {
		t.Fatal("resolved key length = nil, want keyword-matched evidence")
	}
	if got.Provenance != "constant" || got.Bits == nil || *got.Bits != 256 {
		t.Fatalf("resolved key length = %#v, want constant 256 bits", got)
	}
	if got.SourceCall.FunctionName != "hashlib.pbkdf2_hmac" || got.SourceCall.ParameterIndex != 4 {
		t.Fatalf("source_call = %#v, want hashlib.pbkdf2_hmac parameter 4", got.SourceCall)
	}
}

// TestResolvedKeyLength_Python_ModuleConstant (row C §5.2 step 3a,
// python-parser-parity-2) pins that `dklen=KEY_LEN` resolves the same way
// once ResolvedValue already carries the module-constant's resolved text
// (row 20's moduleConsts -> ArgumentSources -> resolveSimpleExportParameterValue
// chain, exercised end-to-end elsewhere; this test isolates step 3a's own
// ResolvedValue-first precedence).
func TestResolvedKeyLength_Python_ModuleConstant(t *testing.T) {
	t.Parallel()

	ctx := newExportBuildContext(&engine.DepScanResult{
		CallGraph: &callgraph.CallGraph{},
		Ecosystem: "python",
	})
	call, parameters := pythonKDFCall("dklen=KEY_LEN", "32")
	matches := contractMatchesForCall(ctx, call, len(call.Arguments))
	got := resolvedKeyLengthFromContract(ctx, matches, call, parameters, nil)
	if got == nil {
		t.Fatal("resolved key length = nil, want keyword-matched evidence")
	}
	if got.Provenance != "constant" || got.Bits == nil || *got.Bits != 256 {
		t.Fatalf("resolved key length = %#v, want constant 256 bits", got)
	}
}

// TestResolvedKeyLength_Python_NonConstantStaysUnknown (row C §5.2 step 3a,
// python-parser-parity-2) pins that a keyword match with an unresolvable
// value still emits a record (matching resolvedKeyLengthForRole's own
// steps-1-2 "unknown" convention) — never silently drops the match.
func TestResolvedKeyLength_Python_NonConstantStaysUnknown(t *testing.T) {
	t.Parallel()

	ctx := newExportBuildContext(&engine.DepScanResult{
		CallGraph: &callgraph.CallGraph{},
		Ecosystem: "python",
	})
	call, parameters := pythonKDFCall("dklen=user_len", "")
	matches := contractMatchesForCall(ctx, call, len(call.Arguments))
	got := resolvedKeyLengthFromContract(ctx, matches, call, parameters, nil)
	if got == nil {
		t.Fatal("resolved key length = nil, want keyword-matched evidence with unknown provenance")
	}
	if got.Provenance != "unknown" || got.Bits != nil {
		t.Fatalf("resolved key length = %#v, want unknown provenance and nil bits", got)
	}
}

// TestResolvedKeyLength_Python_PositionalLength (row C §5.2 step 3b,
// python-parser-parity-2, spec scenario "Positional call without
// call-site type evidence still resolves") pins that a purely positional
// `hashlib.pbkdf2_hmac('sha256', password, salt, 100000, 32)` resolves when
// no declared-type evidence exists for the dklen parameter at all.
func TestResolvedKeyLength_Python_PositionalLength(t *testing.T) {
	t.Parallel()

	ctx := newExportBuildContext(&engine.DepScanResult{
		CallGraph: &callgraph.CallGraph{},
		Ecosystem: "python",
	})
	call, parameters := pythonKDFCall("32", "32")
	matches := contractMatchesForCall(ctx, call, len(call.Arguments))
	got := resolvedKeyLengthFromContract(ctx, matches, call, parameters, nil)
	if got == nil {
		t.Fatal("resolved key length = nil, want positional constant evidence")
	}
	if got.Provenance != "constant" || got.Bits == nil || *got.Bits != 256 {
		t.Fatalf("resolved key length = %#v, want constant 256 bits", got)
	}
	if got.SourceCall.ParameterIndex != 4 {
		t.Fatalf("source_call.parameter_index = %d, want 4", got.SourceCall.ParameterIndex)
	}
}

// TestResolvedKeyLength_Python_PositionalNonConstantStaysAbsent (row C
// §5.2 step 3b, python-parser-parity-2, spec scenario "a non-constant
// positional argument MUST resolve nothing") pins that step 3b, unlike
// 3a, NEVER emits an "unknown" record for an unresolvable positional
// value — silence is correct once every step has had its chance.
func TestResolvedKeyLength_Python_PositionalNonConstantStaysAbsent(t *testing.T) {
	t.Parallel()

	ctx := newExportBuildContext(&engine.DepScanResult{
		CallGraph: &callgraph.CallGraph{},
		Ecosystem: "python",
	})
	call, parameters := pythonKDFCall("user_len", "")
	matches := contractMatchesForCall(ctx, call, len(call.Arguments))
	got := resolvedKeyLengthFromContract(ctx, matches, call, parameters, nil)
	if got != nil {
		t.Fatalf("resolved key length = %#v, want nil (non-constant positional value)", got)
	}
}

// TestResolvedKeyLength_JavaUnchangedByKeywordPath (T0.10, row C,
// python-parser-parity-2) pins that steps 3a/3b never change a Java call
// site's resolution: Java's own extractCallArguments never produces
// name=value argument text (step 3a's structural precondition never
// holds), and this exact "same arity non-int overload is excluded"
// scenario already proves step 1 rejecting a type mismatch leaves the
// call-site's OWN declared type present at the keySize index — which is
// exactly what makes step 3b's "no declared type evidence" precondition
// fail too, leaving the result unchanged (nil).
func TestResolvedKeyLength_JavaUnchangedByKeywordPath(t *testing.T) {
	t.Parallel()

	ctx := newExportBuildContext(&engine.DepScanResult{
		CallGraph: &callgraph.CallGraph{},
		Ecosystem: "java",
	})
	keyGeneratorInit := callgraph.FunctionID{Package: "javax.crypto", Type: "KeyGenerator", Name: "init#1"}

	t.Run("declared-type mismatch stays nil", func(t *testing.T) {
		call := &callgraph.FunctionCall{
			Callee:    keyGeneratorInit,
			FilePath:  "KeyFlow.java",
			Line:      9,
			Arguments: []string{"parameters"},
		}
		parameters := []callGraphParameter{{
			ParameterIndex:     0,
			ArgumentExpression: "parameters",
		}}
		matches := contractMatchesForCall(ctx, call, len(call.Arguments))
		got := resolvedKeyLengthFromContract(ctx, matches, call, parameters, []string{"java.security.spec.AlgorithmParameterSpec"})
		if got != nil {
			t.Fatalf("resolved key length = %#v, want nil — steps 3a/3b (row C) must never resolve a Java call site", got)
		}
	})

	// G7 (PR #310 phase-2 review): step 3b (design.md §5.2) is a Python-only
	// path. A resolved variable with NO declared-type evidence at all (no
	// SourceNode.DeclaredType, no resolver-supplied parameterTypes) still
	// satisfies step 3b's "no type evidence" precondition on ANY ecosystem
	// — an ungated step 3b would fabricate a "constant" record for
	// KeyGenerator.init(keySize) here, a shape steps 1-2 never resolved
	// before row C either.
	t.Run("resolved variable with no type evidence at all stays nil", func(t *testing.T) {
		call := &callgraph.FunctionCall{
			Callee:    keyGeneratorInit,
			FilePath:  "KeyFlow.java",
			Line:      11,
			Arguments: []string{"keySize"},
		}
		parameters := []callGraphParameter{{
			ParameterIndex:     0,
			ArgumentExpression: "keySize",
			ResolvedValue:      "256",
		}}
		matches := contractMatchesForCall(ctx, call, len(call.Arguments))
		got := resolvedKeyLengthFromContract(ctx, matches, call, parameters, nil)
		if got != nil {
			t.Fatalf("resolved key length = %#v, want nil — step 3b must never resolve a non-Python call site", got)
		}
	})
}

// TestResolvedKeyLength_Python_KeywordAtDifferentPositionNeverReadPositionally
// (G2, PR #310 phase-2 review) pins that a keyword argument whose NAME does
// not match the keySize role — but which happens to sit at the keySize
// role's declared POSITIONAL index — is never misread as that role's raw
// positional value. `PBKDF2(password, salt, count=1000)` previously
// resolved 8000 bits (1000 bytes) by reading "count"'s value in place of
// the (omitted) `dkLen` argument.
func TestResolvedKeyLength_Python_KeywordAtDifferentPositionNeverReadPositionally(t *testing.T) {
	t.Parallel()

	ctx := newExportBuildContext(&engine.DepScanResult{
		CallGraph: &callgraph.CallGraph{},
		Ecosystem: "python",
	})
	call := &callgraph.FunctionCall{
		Callee:    callgraph.FunctionID{Package: "Crypto.Protocol.KDF", Type: "PBKDF2", Name: constructorMethodName},
		FilePath:  "derive.py",
		Line:      9,
		Arguments: []string{"password", "salt", "count=1000"},
	}
	parameters := []callGraphParameter{
		{ParameterIndex: 0, ArgumentExpression: "password"},
		{ParameterIndex: 1, ArgumentExpression: "salt"},
		{ParameterIndex: 2, ArgumentExpression: "count=1000", ResolvedValue: "1000"},
	}
	matches := contractMatchesForCall(ctx, call, len(call.Arguments))
	got := resolvedKeyLengthFromContract(ctx, matches, call, parameters, nil)
	if got != nil {
		t.Fatalf("resolved key length = %#v, want nil (a keyword arg for a DIFFERENT parameter must never be read positionally)", got)
	}
}

// TestResolvedKeyLength_Python_EveryListedAPI (row C, python-parser-parity-2)
// is a table over every KDF API this row's KB coverage verified against a
// primary source. Batch 2 covered pyca-cryptography and hashlib (verified
// against the locally installed package/interpreter, offline); batch 3
// adds argon2-cffi, bcrypt, pycryptodome, and pycryptodomex (verified
// against each library's own GitHub source — network access was available
// for this batch, see apply-progress.md for exact URLs/signatures).
// Exercises the keyword form for every entry, and the positional form
// wherever the real API's own signature allows it (hashlib.scrypt's dklen
// is keyword-only in real Python, so only its keyword form is tested).
func TestResolvedKeyLength_Python_EveryListedAPI(t *testing.T) {
	t.Parallel()

	ctx := newExportBuildContext(&engine.DepScanResult{
		CallGraph: &callgraph.CallGraph{},
		Ecosystem: "python",
	})

	tests := []struct {
		name           string
		callee         callgraph.FunctionID
		args           []string
		keywordIndex   int
		testPositional bool
	}{
		{
			name:         "cryptography.PBKDF2HMAC keyword length",
			callee:       callgraph.FunctionID{Package: "cryptography.hazmat.primitives.kdf.pbkdf2", Type: "PBKDF2HMAC", Name: constructorMethodName},
			args:         []string{"algorithm", "length=32", "salt", "100000"},
			keywordIndex: 1, testPositional: true,
		},
		{
			name:         "cryptography.Scrypt keyword length",
			callee:       callgraph.FunctionID{Package: "cryptography.hazmat.primitives.kdf.scrypt", Type: "Scrypt", Name: constructorMethodName},
			args:         []string{"salt", "length=32", "2**14", "8", "1"},
			keywordIndex: 1, testPositional: true,
		},
		{
			name:         "cryptography.HKDF keyword length",
			callee:       callgraph.FunctionID{Package: "cryptography.hazmat.primitives.kdf.hkdf", Type: "HKDF", Name: constructorMethodName},
			args:         []string{"algorithm", "length=32", "salt", "info"},
			keywordIndex: 1, testPositional: true,
		},
		{
			name:         "cryptography.HKDFExpand keyword length",
			callee:       callgraph.FunctionID{Package: "cryptography.hazmat.primitives.kdf.hkdf", Type: "HKDFExpand", Name: constructorMethodName},
			args:         []string{"algorithm", "length=32", "info"},
			keywordIndex: 1, testPositional: true,
		},
		{
			name:         "cryptography.ConcatKDFHash keyword length",
			callee:       callgraph.FunctionID{Package: "cryptography.hazmat.primitives.kdf.concatkdf", Type: "ConcatKDFHash", Name: constructorMethodName},
			args:         []string{"algorithm", "length=32", "otherinfo"},
			keywordIndex: 1, testPositional: true,
		},
		{
			name:         "cryptography.X963KDF keyword length",
			callee:       callgraph.FunctionID{Package: "cryptography.hazmat.primitives.kdf.x963kdf", Type: "X963KDF", Name: constructorMethodName},
			args:         []string{"algorithm", "length=32", "sharedinfo"},
			keywordIndex: 1, testPositional: true,
		},
		{
			name:         "hashlib.pbkdf2_hmac keyword dklen",
			callee:       callgraph.FunctionID{Package: "hashlib", Name: "pbkdf2_hmac"},
			args:         []string{"'sha256'", "password", "salt", "100000", "dklen=32"},
			keywordIndex: 4, testPositional: true,
		},
		{
			name:         "hashlib.scrypt keyword dklen",
			callee:       callgraph.FunctionID{Package: "hashlib", Name: "scrypt"},
			args:         []string{"password", "salt", "n", "r", "p", "maxmem", "dklen=32"},
			keywordIndex: 6, testPositional: false,
		},
		{
			name:         "argon2.PasswordHasher keyword hash_len",
			callee:       callgraph.FunctionID{Package: "argon2", Type: "PasswordHasher", Name: constructorMethodName},
			args:         []string{"time_cost", "memory_cost", "parallelism", "hash_len=32"},
			keywordIndex: 3, testPositional: true,
		},
		{
			name:         "argon2.low_level.hash_secret keyword hash_len",
			callee:       callgraph.FunctionID{Package: "argon2.low_level", Name: "hash_secret"},
			args:         []string{"secret", "salt", "time_cost", "memory_cost", "parallelism", "hash_len=32", "type"},
			keywordIndex: 5, testPositional: true,
		},
		{
			name:         "bcrypt.kdf keyword desired_key_bytes",
			callee:       callgraph.FunctionID{Package: "bcrypt", Name: "kdf"},
			args:         []string{"password", "salt", "desired_key_bytes=32", "rounds"},
			keywordIndex: 2, testPositional: true,
		},
		{
			name:         "Crypto.Protocol.KDF.PBKDF2 keyword dkLen",
			callee:       callgraph.FunctionID{Package: "Crypto.Protocol.KDF", Type: "PBKDF2", Name: constructorMethodName},
			args:         []string{"password", "salt", "dkLen=32"},
			keywordIndex: 2, testPositional: true,
		},
		{
			name:         "Crypto.Protocol.KDF.scrypt keyword key_len",
			callee:       callgraph.FunctionID{Package: "Crypto.Protocol.KDF", Name: "scrypt"},
			args:         []string{"password", "salt", "key_len=32", "n", "r", "p"},
			keywordIndex: 2, testPositional: true,
		},
		{
			name:         "Crypto.Protocol.KDF.HKDF keyword key_len",
			callee:       callgraph.FunctionID{Package: "Crypto.Protocol.KDF", Type: "HKDF", Name: constructorMethodName},
			args:         []string{"master", "key_len=32", "salt", "hashmod"},
			keywordIndex: 1, testPositional: true,
		},
		{
			name:         "Crypto.Protocol.KDF.PBKDF1 keyword dkLen",
			callee:       callgraph.FunctionID{Package: "Crypto.Protocol.KDF", Type: "PBKDF1", Name: constructorMethodName},
			args:         []string{"password", "salt", "dkLen=32"},
			keywordIndex: 2, testPositional: true,
		},
		{
			name:         "Cryptodome.Protocol.KDF.PBKDF2 keyword dkLen",
			callee:       callgraph.FunctionID{Package: "Cryptodome.Protocol.KDF", Type: "PBKDF2", Name: constructorMethodName},
			args:         []string{"password", "salt", "dkLen=32"},
			keywordIndex: 2, testPositional: true,
		},
		{
			name:         "Cryptodome.Protocol.KDF.scrypt keyword key_len",
			callee:       callgraph.FunctionID{Package: "Cryptodome.Protocol.KDF", Name: "scrypt"},
			args:         []string{"password", "salt", "key_len=32", "n", "r", "p"},
			keywordIndex: 2, testPositional: true,
		},
		{
			name:         "Cryptodome.Protocol.KDF.HKDF keyword key_len",
			callee:       callgraph.FunctionID{Package: "Cryptodome.Protocol.KDF", Type: "HKDF", Name: constructorMethodName},
			args:         []string{"master", "key_len=32", "salt", "hashmod"},
			keywordIndex: 1, testPositional: true,
		},
		{
			name:         "Cryptodome.Protocol.KDF.PBKDF1 keyword dkLen",
			callee:       callgraph.FunctionID{Package: "Cryptodome.Protocol.KDF", Type: "PBKDF1", Name: constructorMethodName},
			args:         []string{"password", "salt", "dkLen=32"},
			keywordIndex: 2, testPositional: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parameters := make([]callGraphParameter, len(tt.args))
			for i, arg := range tt.args {
				resolvedValue := ""
				if i == tt.keywordIndex {
					resolvedValue = "32"
				}
				parameters[i] = callGraphParameter{ParameterIndex: i, ArgumentExpression: arg, ResolvedValue: resolvedValue}
			}
			call := &callgraph.FunctionCall{Callee: tt.callee, FilePath: "derive.py", Line: 3, Arguments: tt.args}
			matches := contractMatchesForCall(ctx, call, len(tt.args))
			got := resolvedKeyLengthFromContract(ctx, matches, call, parameters, nil)
			if got == nil || got.Provenance != "constant" || got.Bits == nil || *got.Bits != 256 {
				t.Fatalf("keyword form: resolved key length = %#v, want constant 256 bits", got)
			}

			if !tt.testPositional {
				return
			}
			positionalArgs := make([]string, len(tt.args))
			copy(positionalArgs, tt.args)
			positionalArgs[tt.keywordIndex] = "32"
			positionalParameters := make([]callGraphParameter, len(positionalArgs))
			for i, arg := range positionalArgs {
				resolvedValue := ""
				if i == tt.keywordIndex {
					resolvedValue = "32"
				}
				positionalParameters[i] = callGraphParameter{ParameterIndex: i, ArgumentExpression: arg, ResolvedValue: resolvedValue}
			}
			positionalCall := &callgraph.FunctionCall{Callee: tt.callee, FilePath: "derive.py", Line: 4, Arguments: positionalArgs}
			positionalMatches := contractMatchesForCall(ctx, positionalCall, len(positionalArgs))
			gotPositional := resolvedKeyLengthFromContract(ctx, positionalMatches, positionalCall, positionalParameters, nil)
			if gotPositional == nil || gotPositional.Provenance != "constant" || gotPositional.Bits == nil || *gotPositional.Bits != 256 {
				t.Fatalf("positional form: resolved key length = %#v, want constant 256 bits", gotPositional)
			}
		})
	}
}
