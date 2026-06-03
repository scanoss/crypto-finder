package callgraph

import "testing"

// findCallByMethod returns the first call in fn whose resolved callee method
// base name matches method and whose Raw contains rawContains (use "" to skip
// the Raw filter). Returns nil when no call matches.
func findCallByMethod(fn *FunctionDecl, method, rawContains string) *FunctionCall {
	for i := range fn.Calls {
		c := &fn.Calls[i]
		if BaseFunctionName(c.Callee.Name) != method {
			continue
		}
		if rawContains != "" && !containsSubstr(c.Raw, rawContains) {
			continue
		}
		return c
	}
	return nil
}

func containsSubstr(s, sub string) bool {
	return sub == "" || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestJavaParser_StatefulObject_ReceiverAndAssignedVar verifies that for the
// BouncyCastle lightweight digest pattern, the constructor records the variable
// its result is assigned to (AssignedVar) and the subsequent lifecycle calls
// record the variable they are invoked on (ReceiverVar). This is the spine of
// callgraph-derived supporting calls for stateful crypto objects.
func TestJavaParser_StatefulObject_ReceiverAndAssignedVar(t *testing.T) {
	src := `package com.example;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.util.encoders.Hex;
class Sample {
    public String hashSHA3_256(String input) {
        SHA3Digest digest = new SHA3Digest(256);
        byte[] inputBytes = input.getBytes();
        digest.update(inputBytes, 0, inputBytes.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return Hex.toHexString(hash);
    }
}
`
	fns := parseJavaInline(t, src)
	fn := findFunctionByName(fns, "hashSHA3_256")
	if fn == nil {
		t.Fatal("hashSHA3_256 not found")
	}

	ctor := findCallByMethod(fn, "<init>", "SHA3Digest")
	if ctor == nil {
		t.Fatal("SHA3Digest constructor call not found")
	}
	if ctor.AssignedVar != "digest" {
		t.Errorf("constructor AssignedVar = %q, want %q", ctor.AssignedVar, "digest")
	}

	for _, method := range []string{"update", "doFinal", "getDigestSize"} {
		call := findCallByMethod(fn, method, "")
		if call == nil {
			t.Fatalf("call to %s not found", method)
		}
		if call.ReceiverVar != "digest" {
			t.Errorf("%s ReceiverVar = %q, want %q", method, call.ReceiverVar, "digest")
		}
	}

	// getBytes() is invoked on `input`, not on the crypto object — it must NOT
	// be attributed to `digest`.
	if gb := findCallByMethod(fn, "getBytes", ""); gb != nil && gb.ReceiverVar == "digest" {
		t.Errorf("getBytes ReceiverVar = %q, want it not attributed to digest", gb.ReceiverVar)
	}
}

// TestJavaParser_FluentChain_ChainIDAndAssignedVar verifies that for the
// Password4J fluent builder pattern, the chain links share a ChainID, the chain
// root records the variable it is assigned to, and a follow-up call on that
// variable records it as ReceiverVar.
func TestJavaParser_FluentChain_ChainIDAndAssignedVar(t *testing.T) {
	src := `package com.example;
import com.password4j.Password;
import com.password4j.Hash;
class Sample {
    public String hashPasswordBcrypt(String plainPassword) {
        Hash hash = Password.hash(plainPassword).addRandomSalt().withBcrypt();
        return hash.getResult();
    }
}
`
	fns := parseJavaInline(t, src)
	fn := findFunctionByName(fns, "hashPasswordBcrypt")
	if fn == nil {
		t.Fatal("hashPasswordBcrypt not found")
	}

	hashStart := findCallByMethod(fn, "hash", "Password.hash")
	addSalt := findCallByMethod(fn, "addRandomSalt", "")
	withBcrypt := findCallByMethod(fn, "withBcrypt", "")
	if hashStart == nil || addSalt == nil || withBcrypt == nil {
		t.Fatalf("chain links not all found: hash=%v addRandomSalt=%v withBcrypt=%v",
			hashStart != nil, addSalt != nil, withBcrypt != nil)
	}

	if withBcrypt.ChainID == "" {
		t.Fatal("withBcrypt ChainID is empty; chain grouping not populated")
	}
	if hashStart.ChainID != withBcrypt.ChainID || addSalt.ChainID != withBcrypt.ChainID {
		t.Errorf("chain links do not share a ChainID: hash=%q addRandomSalt=%q withBcrypt=%q",
			hashStart.ChainID, addSalt.ChainID, withBcrypt.ChainID)
	}

	// The chain root (terminal withBcrypt) is what binds to `hash`.
	if withBcrypt.AssignedVar != "hash" {
		t.Errorf("withBcrypt AssignedVar = %q, want %q", withBcrypt.AssignedVar, "hash")
	}

	getResult := findCallByMethod(fn, "getResult", "")
	if getResult == nil {
		t.Fatal("getResult call not found")
	}
	if getResult.ReceiverVar != "hash" {
		t.Errorf("getResult ReceiverVar = %q, want %q", getResult.ReceiverVar, "hash")
	}
}
