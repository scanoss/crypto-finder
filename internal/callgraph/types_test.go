package callgraph

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestFunctionDecl_HasReturnSourcesAndInferredReturn asserts that FunctionDecl
// carries the two new inference-related fields at zero values.
func TestFunctionDecl_HasReturnSourcesAndInferredReturn(t *testing.T) {
	var decl FunctionDecl

	if decl.ReturnSources != nil {
		t.Errorf("ReturnSources zero value: got %v, want nil", decl.ReturnSources)
	}

	if decl.InferredReturn != nil {
		t.Errorf("InferredReturn zero value: got %v, want nil", decl.InferredReturn)
	}
}

// TestInferredReturn_FieldShape asserts that InferredReturn has the expected
// fields with the correct types and zero values.
func TestInferredReturn_FieldShape(t *testing.T) {
	ir := InferredReturn{}

	if ir.Type != "" {
		t.Errorf("Type zero value: got %q, want empty string", ir.Type)
	}

	if !reflect.DeepEqual(ir.TypeRef, TypeRef{}) {
		t.Errorf("TypeRef zero value: got %v, want zero TypeRef", ir.TypeRef)
	}

	if ir.Confidence != "" {
		t.Errorf("Confidence zero value: got %q, want empty string", ir.Confidence)
	}

	if ir.Origin != "" {
		t.Errorf("Origin zero value: got %q, want empty string", ir.Origin)
	}

	if ir.Provenance != nil {
		t.Errorf("Provenance zero value: got %v, want nil", ir.Provenance)
	}

	// Compile-time shape check: populate all fields to verify the struct accepts
	// the expected types. This will fail to compile if any field type changes.
	populated := InferredReturn{
		Type:       "javax.crypto.SecretKey",
		TypeRef:    TypeRef{Name: "SecretKey"},
		Confidence: ConfidenceHigh,
		Origin:     OriginKBDirect,
		Provenance: []SourceNode{{Type: "CALL_RESULT"}},
	}
	if populated.Type != "javax.crypto.SecretKey" {
		t.Errorf("populated.Type = %q, want %q", populated.Type, "javax.crypto.SecretKey")
	}
	if populated.TypeRef.Name != "SecretKey" {
		t.Errorf("populated.TypeRef.Name = %q, want %q", populated.TypeRef.Name, "SecretKey")
	}
	if populated.Confidence != ConfidenceHigh {
		t.Errorf("populated.Confidence = %q, want %q", populated.Confidence, ConfidenceHigh)
	}
	if populated.Origin != OriginKBDirect {
		t.Errorf("populated.Origin = %q, want %q", populated.Origin, OriginKBDirect)
	}
	if len(populated.Provenance) != 1 {
		t.Errorf("populated.Provenance len = %d, want 1", len(populated.Provenance))
	}
}

// TestFunctionDecl_InferredReturn_ZeroMarshal asserts that a FunctionDecl with a
// nil InferredReturn and empty ReturnSources marshals cleanly (the engine-facing
// fields do not produce unexpected JSON). The export layer (Batch 5) is
// responsible for the omitempty JSON surface; this test only validates that the
// types round-trip without error.
func TestFunctionDecl_InferredReturn_ZeroMarshal(t *testing.T) {
	decl := FunctionDecl{
		ID:       FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "getInstance#1"},
		FilePath: "Cipher.java",
	}

	b, err := json.Marshal(decl)
	if err != nil {
		t.Fatalf("json.Marshal FunctionDecl: %v", err)
	}

	var roundtrip FunctionDecl
	if err := json.Unmarshal(b, &roundtrip); err != nil {
		t.Fatalf("json.Unmarshal FunctionDecl: %v", err)
	}

	if roundtrip.InferredReturn != nil {
		t.Errorf("InferredReturn after round-trip: got %v, want nil", roundtrip.InferredReturn)
	}
	if roundtrip.ReturnSources != nil {
		t.Errorf("ReturnSources after round-trip: got %v, want nil", roundtrip.ReturnSources)
	}

	// Triangulate: with a populated InferredReturn it should survive the round-trip.
	decl2 := FunctionDecl{
		ID: FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "getInstance#1"},
		InferredReturn: &InferredReturn{
			Type:       "javax.crypto.SecretKey",
			Confidence: "high",
			Origin:     "kb-direct",
		},
		ReturnSources: []SourceNode{
			{Type: "CALL_RESULT", Name: "generateKey"},
		},
	}

	b2, err := json.Marshal(decl2)
	if err != nil {
		t.Fatalf("json.Marshal populated FunctionDecl: %v", err)
	}

	var rt2 FunctionDecl
	if err := json.Unmarshal(b2, &rt2); err != nil {
		t.Fatalf("json.Unmarshal populated FunctionDecl: %v", err)
	}
	if rt2.InferredReturn == nil {
		t.Fatal("InferredReturn nil after round-trip with populated value")
	}
	if rt2.InferredReturn.Type != "javax.crypto.SecretKey" {
		t.Errorf("InferredReturn.Type = %q, want %q", rt2.InferredReturn.Type, "javax.crypto.SecretKey")
	}
	if len(rt2.ReturnSources) != 1 {
		t.Errorf("ReturnSources len = %d, want 1", len(rt2.ReturnSources))
	}
}
