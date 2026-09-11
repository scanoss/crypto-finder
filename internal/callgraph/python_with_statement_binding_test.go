package callgraph

import "testing"

// TestPythonParser_WithStatementBindsAssignedVar pins the `with <call> as x:`
// case of pythonAssignedVarFromParent.
//
// BEFORE THIS CASE EXISTED the walker BOUND the name (recordPythonWalkBinder's
// asPattern arm marks it a local) but recorded no AssignedVar, so
// propagatePythonAssignedVarTypesForDecl had nothing to attach the callee's
// return type to, and every receiver call on a context-manager binding stayed
// uncontracted. Measured on a probe package for liboqs-python, whose entire
// documented API is context-managed: with the constructor contracted and this
// case absent, four call sites in the `with`-statement probe module emitted the
// CONSUMER'S OWN VARIABLE NAME -- `probeconsumer.k.generate_keypair()`,
// `probeconsumer.k.encap_secret(?)`, `probeconsumer.s.generate_keypair()`,
// `probeconsumer.s.sign(?)` -- which is the uncontracted shape and joins
// nothing. With it they resolve to `oqs.KeyEncapsulation.generate_keypair()`,
// `oqs.KeyEncapsulation.encap_secret(?): builtins.tuple`,
// `oqs.Signature.generate_keypair()` and `oqs.Signature.sign(?): builtins.bytes`.
//
// The gap is not specific to one library: `with` is the documented idiom for a
// whole class of crypto APIs that hold an OS or FFI resource.
func TestPythonParser_WithStatementBindsAssignedVar(t *testing.T) {
	src := `import oqs

def roundtrip(public_key):
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        return kem.encap_secret(public_key)
`
	fns := parsePythonInline(t, src)

	fn := findPythonFuncByName(fns, "roundtrip")
	if fn == nil {
		t.Fatal("roundtrip function not found")
	}
	ctor := findPythonCallByMethod(fn, "KeyEncapsulation")
	if ctor == nil {
		t.Fatal("KeyEncapsulation constructor call not found")
	}
	if ctor.AssignedVar != "kem" {
		t.Errorf("KeyEncapsulation() AssignedVar = %q, want %q -- a `with ... as kem` "+
			"binding must be treated as an assignment for typing purposes",
			ctor.AssignedVar, "kem")
	}

	sink := findPythonCallByMethod(fn, "encap_secret")
	if sink == nil {
		t.Fatal("encap_secret call not found")
	}
	if sink.ReceiverVar != "kem" {
		t.Errorf("encap_secret ReceiverVar = %q, want %q", sink.ReceiverVar, "kem")
	}
}

// TestPythonParser_WithStatementMultipleItemsBindEachTarget pins the
// multi-item form, where one `with` statement carries two independent
// bindings. Each must take its own call's result, not the other's.
func TestPythonParser_WithStatementMultipleItemsBindEachTarget(t *testing.T) {
	src := `import oqs

def pair(public_key, message):
    with oqs.KeyEncapsulation("ML-KEM-768") as kem, oqs.Signature("ML-DSA-65") as signer:
        kem.encap_secret(public_key)
        signer.sign(message)
`
	fns := parsePythonInline(t, src)

	fn := findPythonFuncByName(fns, "pair")
	if fn == nil {
		t.Fatal("pair function not found")
	}
	for method, want := range map[string]string{
		"KeyEncapsulation": "kem",
		"Signature":        "signer",
	} {
		call := findPythonCallByMethod(fn, method)
		if call == nil {
			t.Fatalf("%s constructor call not found", method)
		}
		if call.AssignedVar != want {
			t.Errorf("%s() AssignedVar = %q, want %q", method, call.AssignedVar, want)
		}
	}
}

// TestPythonParser_AssignedVarPreExistingShapesStillHold is the regression half
// of the shared-behavior change (campaign 5.4: prove the old cases still hold
// with a test that pins them).
//
// The new `as_pattern` arm returns early, so it can only affect a call whose
// PARENT is an as_pattern. These three shapes reach the function through the
// other branches and must be untouched.
func TestPythonParser_AssignedVarPreExistingShapesStillHold(t *testing.T) {
	cases := []struct {
		name   string
		src    string
		fn     string
		method string
		want   string
	}{
		{
			name: "plain identifier assignment",
			src: `import oqs

def f():
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    return kem
`,
			fn: "f", method: "KeyEncapsulation", want: "kem",
		},
		{
			name: "self attribute assignment",
			src: `import oqs

class Holder:
    def __init__(self):
        self.kem = oqs.KeyEncapsulation("ML-KEM-768")
`,
			fn: constructorMethodName, method: "KeyEncapsulation", want: "self.kem",
		},
		{
			name: "unassigned call has no AssignedVar",
			src: `import oqs

def f():
    oqs.KeyEncapsulation("ML-KEM-768")
`,
			fn: "f", method: "KeyEncapsulation", want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fns := parsePythonInline(t, tc.src)
			fn := findPythonFuncByName(fns, tc.fn)
			if fn == nil {
				t.Fatalf("%s not found", tc.fn)
			}
			call := findPythonCallByMethod(fn, tc.method)
			if call == nil {
				t.Fatalf("%s call not found", tc.method)
			}
			if call.AssignedVar != tc.want {
				t.Errorf("AssignedVar = %q, want %q", call.AssignedVar, tc.want)
			}
		})
	}
}

// TestPythonParser_ExceptAsBindingAlsoCarriesTheTarget documents a
// deliberate consequence rather than an accident: `except E as e:` is also an
// as_pattern, so a CALL bound that way now carries its target too. That is
// correct -- if the bound value is a call, its return type is what the name
// holds -- and pinning it here means a future narrowing of the arm is a
// visible decision.
func TestPythonParser_ExceptAsBindingAlsoCarriesTheTarget(t *testing.T) {
	src := `import oqs

def f():
    try:
        pass
    except oqs.MechanismNotSupportedError() as err:
        return err
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "f")
	if fn == nil {
		t.Fatal("f not found")
	}
	call := findPythonCallByMethod(fn, "MechanismNotSupportedError")
	if call == nil {
		t.Skip("the grammar did not produce a call node for the except target; " +
			"nothing to pin here")
	}
	if call.AssignedVar != "err" {
		t.Errorf("AssignedVar = %q, want %q", call.AssignedVar, "err")
	}
}
