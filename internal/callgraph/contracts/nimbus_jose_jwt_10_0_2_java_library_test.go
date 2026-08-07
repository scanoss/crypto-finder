package contracts_test

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// TestLoadEmbeddedJava_NimbusJoseJwt1002JSONLifecycle is the
// scanoss/crypto-finder#184 acceptance test: the version-pinned 10.0.2 KB
// (nimbus-jose-jwt-10.0.2.yaml) loads alongside the pre-existing 9.37.3 KB
// (nimbus-jose-jwt.yaml) without conflict, contracts the new
// JOSEObjectJSON/JWSObjectJSON/JWEObjectJSON JSON-serialization family --
// parse/construct (factory), sign/verify and encrypt/decrypt (operation),
// and the general/flattened serialization methods (output) -- and that the
// 9.37.3 JWSObject/JWEObject compact-serialization contracts are untouched.
func TestLoadEmbeddedJava_NimbusJoseJwt1002JSONLifecycle(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	const (
		joseObjectJSON = "com.nimbusds.jose.JOSEObjectJSON"
		jwsObjectJSON  = "com.nimbusds.jose.JWSObjectJSON"
		jweObjectJSON  = "com.nimbusds.jose.JWEObjectJSON"
	)

	tests := []struct {
		method string
		arity  int
		want   string
		role   string
	}{
		// JOSEObjectJSON shared abstract base: only the STATIC parse()
		// dispatcher is authored here (no receiver-variable ambiguity for a
		// static call). The dispatcher's only non-throwing branch always
		// returns a JWSObjectJSON (JWE JSON parsing isn't supported yet in
		// 10.0.2) -- a more informative concrete type than the declared
		// abstract base.
		{joseObjectJSON + ".parse", 1, jwsObjectJSON, "factory"},

		// JWSObjectJSON.
		{jwsObjectJSON + ".<init>", 1, jwsObjectJSON, "factory"},
		{jwsObjectJSON + ".sign", 2, "void", "operation"},
		{jwsObjectJSON + ".sign", 3, "void", "operation"},
		// The four JOSEObjectJSON-declared abstract methods are authored on
		// THIS concrete class (not the shared abstract base) -- see the
		// nimbus-jose-jwt-10.0.2.yaml audit note on why real-world receiver
		// typing makes base-class authoring unsafe here.
		{jwsObjectJSON + ".toGeneralJSONObject", 0, "java.util.Map", "output"},
		{jwsObjectJSON + ".toFlattenedJSONObject", 0, "java.util.Map", "output"},
		{jwsObjectJSON + ".serializeGeneral", 0, "java.lang.String", "output"},
		{jwsObjectJSON + ".serializeFlattened", 0, "java.lang.String", "output"},
		{jwsObjectJSON + ".parse", 1, jwsObjectJSON, "factory"},

		// JWSObjectJSON.Signature: bridges back to the compact JWSObject.
		{jwsObjectJSON + ".Signature.toJWSObject", 0, "com.nimbusds.jose.JWSObject", "output"},
		{jwsObjectJSON + ".Signature.verify", 1, "boolean", "operation"},

		// JWEObjectJSON.
		{jweObjectJSON + ".<init>", 1, jweObjectJSON, "factory"},
		{jweObjectJSON + ".<init>", 2, jweObjectJSON, "factory"},
		{jweObjectJSON + ".<init>", 4, jweObjectJSON, "factory"},
		{jweObjectJSON + ".<init>", 7, jweObjectJSON, "factory"},
		{jweObjectJSON + ".encrypt", 1, "void", "operation"},
		{jweObjectJSON + ".decrypt", 1, "void", "operation"},
		{jweObjectJSON + ".toGeneralJSONObject", 0, "java.util.Map", "output"},
		{jweObjectJSON + ".toFlattenedJSONObject", 0, "java.util.Map", "output"},
		{jweObjectJSON + ".serializeGeneral", 0, "java.lang.String", "output"},
		{jweObjectJSON + ".serializeFlattened", 0, "java.lang.String", "output"},
		{jweObjectJSON + ".parse", 1, jweObjectJSON, "factory"},

		// JWEObjectJSON.Recipient.
		{jweObjectJSON + ".Recipient.<init>", 2, jweObjectJSON + ".Recipient", "factory"},
		{jweObjectJSON + ".Recipient.toJSONObject", 0, "java.util.Map", "output"},
		{jweObjectJSON + ".Recipient.parse", 1, jweObjectJSON + ".Recipient", "factory"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			c := got[0]
			if c.Return.Type != tt.want || c.Role != tt.role {
				t.Fatalf("%s#%d = %#v, want return %q with role %q", tt.method, tt.arity, c, tt.want, tt.role)
			}
			if c.Return.Confidence != "high" {
				t.Fatalf("%s#%d confidence = %q, want high", tt.method, tt.arity, c.Return.Confidence)
			}
			if c.SourceLibrary != "nimbus-jose-jwt-10.0.2" {
				t.Fatalf("%s#%d source library = %q, want nimbus-jose-jwt-10.0.2", tt.method, tt.arity, c.SourceLibrary)
			}
		})
	}

	// Preserved-meaning check: the pre-existing 9.37.3 compact-serialization
	// entries must be untouched by the new 10.0.2 file (issue AC: "preserving
	// the working 9.37.3 model").
	preserved := []struct {
		method string
		arity  int
		want   string
	}{
		{"com.nimbusds.jose.JWSObject.<init>", 2, "com.nimbusds.jose.JWSObject"},
		{"com.nimbusds.jose.JWSObject.verify", 1, "boolean"},
		{"com.nimbusds.jose.JWEObject.parse", 1, "com.nimbusds.jose.JWEObject"},
		{"com.nimbusds.jose.JWEObject.encrypt", 1, "void"},
	}
	for _, tt := range preserved {
		got := kb.ContractsFor(tt.method, tt.arity)
		if len(got) != 1 || got[0].Return.Type != tt.want || got[0].SourceLibrary != "nimbus-jose-jwt" {
			t.Errorf("preserved 9.37.3 entry %s#%d = %#v, want return %q from nimbus-jose-jwt", tt.method, tt.arity, got, tt.want)
		}
	}

	// Hierarchy: JWSObjectJSON/JWEObjectJSON both extend the new
	// JOSEObjectJSON abstract base; the nested Signature/Recipient value
	// types root directly at java.lang.Object.
	if parents := kb.Hierarchy[jwsObjectJSON]; len(parents) != 1 || parents[0] != joseObjectJSON {
		t.Errorf("JWSObjectJSON hierarchy = %v, want [%s]", parents, joseObjectJSON)
	}
	if parents := kb.Hierarchy[jweObjectJSON]; len(parents) != 1 || parents[0] != joseObjectJSON {
		t.Errorf("JWEObjectJSON hierarchy = %v, want [%s]", parents, joseObjectJSON)
	}
	for _, typ := range []string{joseObjectJSON, jwsObjectJSON, jweObjectJSON, jwsObjectJSON + ".Signature", jweObjectJSON + ".Recipient"} {
		if len(kb.Hierarchy[typ]) == 0 {
			t.Errorf("hierarchy[%q] is empty", typ)
		}
	}
}
