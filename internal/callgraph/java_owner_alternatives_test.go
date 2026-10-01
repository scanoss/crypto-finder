// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package callgraph

import "testing"

// The shape of oauth2-oidc-sdk 9.35 validating an HS256 ID token through
// nimbus-jose-jwt 9.22. Every type the validator and the processor use is
// imported on demand, the processor is held through an interface that
// declares no method of its own, and the verification is inherited: SignedJWT
// takes verify from JWSObject, which dispatches to MACVerifier.
var (
	nimbusJoseShape = artifactFixture{module: "com.nimbusds:nimbus-jose-jwt", version: "9.22", files: map[string]string{
		"com/nimbusds/jose/JWSVerifier.java": `package com.nimbusds.jose;
public interface JWSVerifier { boolean verify(byte[] content); }
`,
		"com/nimbusds/jose/JWSObject.java": `package com.nimbusds.jose;
public class JWSObject {
  public boolean verify(final JWSVerifier verifier) { return verifier.verify(new byte[0]); }
}
`,
		"com/nimbusds/jose/crypto/MACVerifier.java": `package com.nimbusds.jose.crypto;
import com.nimbusds.jose.*;
import javax.crypto.Mac;
public class MACVerifier implements JWSVerifier {
  public boolean verify(byte[] content) {
    try { Mac.getInstance("HmacSHA256"); } catch (Exception e) {}
    return true;
  }
}
`,
		"com/nimbusds/jwt/JWT.java": `package com.nimbusds.jwt;
public interface JWT {}
`,
		"com/nimbusds/jwt/SignedJWT.java": `package com.nimbusds.jwt;
import com.nimbusds.jose.*;
public class SignedJWT extends JWSObject implements JWT {
  public Object getJWTClaimsSet() { return null; }
}
`,
		"com/nimbusds/jwt/proc/JWTProcessor.java": `package com.nimbusds.jwt.proc;
import com.nimbusds.jwt.*;
public interface JWTProcessor { Object process(SignedJWT jwt, Object ctx); }
`,
		"com/nimbusds/jwt/proc/ConfigurableJWTProcessor.java": `package com.nimbusds.jwt.proc;
public interface ConfigurableJWTProcessor extends JWTProcessor {}
`,
		"com/nimbusds/jwt/proc/DefaultJWTProcessor.java": `package com.nimbusds.jwt.proc;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.*;
public class DefaultJWTProcessor implements ConfigurableJWTProcessor {
  public Object process(final SignedJWT signedJWT, Object ctx) {
    JWSVerifier verifier = new MACVerifier();
    return signedJWT.verify(verifier);
  }
}
`,
	}}
	oidcSDKShape = artifactFixture{module: "com.nimbusds:oauth2-oidc-sdk", version: "9.35", files: map[string]string{
		"com/nimbusds/openid/connect/sdk/validators/IDTokenValidator.java": `package com.nimbusds.openid.connect.sdk.validators;
import com.nimbusds.jose.*;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.proc.*;
public class IDTokenValidator {
  public Object validate(final SignedJWT idToken) {
    ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
    return jwtProcessor.process(idToken, null);
  }
}
`,
	}}
	oidcRequiresJose = map[string][]string{"com.nimbusds:oauth2-oidc-sdk": {"com.nimbusds:nimbus-jose-jwt"}}
)

const (
	idTokenValidate   = "com.nimbusds.openid.connect.sdk.validators.(IDTokenValidator).validate#1"
	defaultProcess    = "com.nimbusds.jwt.proc.(DefaultJWTProcessor).process#2"
	jwsObjectVerify   = "com.nimbusds.jose.(JWSObject).verify#1"
	macVerifierVerify = "com.nimbusds.jose.crypto.(MACVerifier).verify#1"
)

// TestReanchorGuessedJavaOwners_OnDemandImports: the parser resolves a type
// imported only on demand without knowing which package declares it, and keyed
// ConfigurableJWTProcessor on the validator's own package and SignedJWT on the
// processor's. Neither exists there, so the ID token's signature check never
// reached nimbus-jose-jwt. The graph knows which on-demand import declares each.
func TestReanchorGuessedJavaOwners_OnDemandImports(t *testing.T) {
	graph := buildArtifactGraph(t, oidcRequiresJose, oidcSDKShape, nimbusJoseShape)

	assertCalls(t, graph, idTokenValidate, "com.nimbusds.jwt.proc.(ConfigurableJWTProcessor).process#2")
	assertCalls(t, graph, idTokenValidate, "com.nimbusds.jwt.proc.(DefaultJWTProcessor).<init>#0")
	assertCalls(t, graph, defaultProcess, "com.nimbusds.jwt.(SignedJWT).verify#1")
}

// TestInheritedDispatch_ThroughEmptyInterface: a call on an interface that
// declares no method of its own names the method it inherits, and reaches the
// classes implementing it. Before, only a type owning a declared method counted
// as known, so the call on ConfigurableJWTProcessor linked nowhere.
func TestInheritedDispatch_ThroughEmptyInterface(t *testing.T) {
	graph := buildArtifactGraph(t, oidcRequiresJose, oidcSDKShape, nimbusJoseShape)

	if !hasCaller(graph, defaultProcess, idTokenValidate) {
		t.Fatalf("Callers[%s] = %v, want %s", defaultProcess, graph.Callers[defaultProcess], idTokenValidate)
	}
	if kind := edgeKindOf(graph, idTokenValidate, defaultProcess); kind != EdgeKindInterfaceDispatch {
		t.Errorf("edge %s -> %s is %q, want %q", idTokenValidate, defaultProcess, kind, EdgeKindInterfaceDispatch)
	}
	if !hasCaller(graph, jwsObjectVerify, defaultProcess) {
		t.Fatalf("Callers[%s] = %v, want %s (SignedJWT inherits verify)", jwsObjectVerify, graph.Callers[jwsObjectVerify], defaultProcess)
	}
	if !hasCaller(graph, macVerifierVerify, jwsObjectVerify) {
		t.Fatalf("Callers[%s] = %v, want %s", macVerifierVerify, graph.Callers[macVerifierVerify], jwsObjectVerify)
	}
}

// TestReanchorGuessedJavaOwners_KeepsUnsettledGuesses: the file's own package
// shadows an on-demand import (JLS 6.4.1), and a name two on-demand imports
// both declare is left as the parser guessed it.
func TestReanchorGuessedJavaOwners_KeepsUnsettledGuesses(t *testing.T) {
	app := artifactFixture{module: "com.example:app", version: "1.0", files: map[string]string{
		"com/example/app/Main.java": `package com.example.app;
import com.example.a.*;
import com.example.b.*;
public class Main {
  public void run(Local local, Shared shared) { local.go(); shared.go(); }
}
`,
		"com/example/app/Local.java": `package com.example.app;
public class Local { public void go() {} }
`,
		"com/example/a/Local.java": `package com.example.a;
public class Local { public void go() {} }
`,
		"com/example/a/Shared.java": `package com.example.a;
public class Shared { public void go() {} }
`,
		"com/example/b/Shared.java": `package com.example.b;
public class Shared { public void go() {} }
`,
	}}
	graph := buildArtifactGraph(t, nil, app)
	caller := "com.example.app.(Main).run#2"

	assertCalls(t, graph, caller, "com.example.app.(Local).go#0")
	assertCalls(t, graph, caller, "com.example.app.(Shared).go#0")
	for _, other := range []string{"com.example.a.(Local).go#0", "com.example.a.(Shared).go#0", "com.example.b.(Shared).go#0"} {
		if hasCaller(graph, other, caller) {
			t.Errorf("Callers[%s] contains %s: the guess must stay unsettled", other, caller)
		}
	}
}

func assertCalls(t *testing.T, graph *CallGraph, callerKey, calleeKey string) {
	t.Helper()
	fn := graph.Functions[callerKey]
	if fn == nil {
		t.Fatalf("no function %s", callerKey)
	}
	var got []string
	for i := range fn.Calls {
		callee := fn.Calls[i].Callee.String()
		if callee == calleeKey {
			return
		}
		got = append(got, callee)
	}
	t.Errorf("%s calls %v, want %s", callerKey, got, calleeKey)
}
