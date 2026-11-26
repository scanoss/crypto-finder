// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"

	gf "github.com/scanoss/reach/graphfrag"

	apiclient "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/appreach"
)

// A Python lock resolves to the same project closure request a Java build
// does: pinned PyPI purls, the direct flags from the lock's tree, the
// requires edges of the lock (extras included, the union of markers), and no
// dev dependency. Each dependency carries its markers and extras.
func TestResolveApplicationClosure_PythonUvLock(t *testing.T) {
	t.Setenv("VIRTUAL_ENV", "")
	dir := filepath.Join("..", "dependency", "testdata", "python", "uv")
	closure, err := ResolveApplicationClosure(context.Background(), dependency.NewPythonResolver(), dir, nil)
	if err != nil {
		t.Fatalf("ResolveApplicationClosure: %v", err)
	}
	if len(closure.CompiledArtifacts()) != 0 {
		t.Errorf("compiled artifacts = %v, want none", closure.CompiledArtifacts())
	}
	request, err := closure.Request(nil, nil, 0)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	want := []apiclient.ApplicationDependency{
		{Purl: "pkg:pypi/certifi", Version: "2025.1.31"},
		{Purl: "pkg:pypi/cffi", Version: "1.17.1", Requires: []string{"pkg:pypi/pycparser"}, Markers: []string{"platform_python_implementation != 'PyPy'"}},
		{Purl: "pkg:pypi/charset-normalizer", Version: "3.4.1"},
		{Purl: "pkg:pypi/cryptography", Version: "44.0.2", Requires: []string{"pkg:pypi/cffi"}, Markers: []string{`extra == "crypto"`}},
		{Purl: "pkg:pypi/idna", Version: "3.10"},
		{Purl: "pkg:pypi/pycparser", Version: "2.22"},
		{Purl: "pkg:pypi/pyjwt", Version: "2.10.1", Direct: true, Requires: []string{"pkg:pypi/cryptography"}, Extras: []string{"crypto"}},
		{Purl: "pkg:pypi/pysocks", Version: "1.7.1", Markers: []string{`extra == "socks"`}},
		{Purl: "pkg:pypi/requests", Version: "2.32.3", Direct: true, Requires: []string{
			"pkg:pypi/certifi", "pkg:pypi/charset-normalizer", "pkg:pypi/idna", "pkg:pypi/pysocks", "pkg:pypi/urllib3",
		}, Extras: []string{"socks"}},
		{Purl: "pkg:pypi/urllib3", Version: "2.3.0"},
	}
	if !reflect.DeepEqual(request.Dependencies, want) {
		t.Errorf("dependencies =\n%+v\nwant\n%+v", request.Dependencies, want)
	}
}

// pythonServedFragment is a dependency fragment as the cards miner stores a
// Python one: graph-algo-py id, the module id left empty.
func pythonServedFragment(purl, version string, functions []string, calls []gf.ExternalCall, exports map[string][]string, ops []gf.CryptoOperation) appreach.Component {
	frag := gf.Fragment{
		Component:        gf.ComponentKey{Purl: purl, Version: version},
		GraphAlgoVersion: gf.GraphAlgoVersionPython,
		ExternalCalls:    calls,
		CryptoOperations: ops,
	}
	for _, f := range functions {
		frag.Functions = append(frag.Functions, gf.Function{Signature: f})
	}
	if exports != nil {
		frag.Exports = make(map[string]string)
		for public, decl := range exports {
			frag.Exports[public] = decl[0]
		}
	}
	return appreach.Component{Fragment: &frag}
}

func pyCall(caller, target string, resolution gf.ResolutionKind, method string, line int) gf.ExternalCall {
	return gf.ExternalCall{Caller: caller, TargetSignature: target, Resolution: resolution, MethodName: method, CallSite: line}
}

func pyOp(function, file string, line int, id string) gf.CryptoOperation {
	return gf.CryptoOperation{Function: function, FindingID: id, RuleID: "python.rule." + id, FilePath: file, StartLine: line}
}

// TestApplicationReachability_PythonLockServed carries the uv lock's request
// through the application reachability engine the API serves it with, over Python
// fragments of the pinned closure:
//   - `jwt.encode` joins pyjwt's declaration through its exports, and pyjwt's
//     typed call reaches cryptography: reachable;
//   - pyjwt's call into idna, which its requires do not name, resolves in the
//     environment (idna is pinned for requests): reachable;
//   - `requests.get` runs `session.request(..)` on an untyped local: requests'
//     own `Session.request` is a candidate, so its finding is unknown, never
//     unreachable;
//   - `params.update(..)` on a parameter (a builtin dict method name) is no
//     candidate of cryptography's `Hash.update`: unreachable;
//   - findings are served under the distribution's module id (pyjwt@2.10.1/..).
func TestApplicationReachability_PythonLockServed(t *testing.T) {
	t.Setenv("VIRTUAL_ENV", "")
	closure, err := ResolveApplicationClosure(context.Background(), dependency.NewPythonResolver(), filepath.Join("..", "dependency", "testdata", "python", "uv"), nil)
	if err != nil {
		t.Fatalf("ResolveApplicationClosure: %v", err)
	}
	request, err := closure.Request(nil, nil, 0)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	deps := make([]appreach.Dependency, 0, len(request.Dependencies))
	versions := make(map[string]string)
	for _, d := range request.Dependencies {
		deps = append(deps, appreach.Dependency{Purl: d.Purl, Version: d.Version, Direct: d.Direct, Requires: d.Requires})
		versions[d.Purl] = d.Version
	}
	var sites gf.GraphFragmentExport
	if err := json.Unmarshal([]byte(`{"schema_version":"`+appreach.SchemaVersion+`",
		"scan_metadata":{"ecosystem":"python","graph_algo_version":"`+gf.GraphAlgoVersionPython+`"},
		"functions":[{"key":"app.auth.token"},{"key":"app.auth.fetch"}],
		"external_calls":[{"caller_key":"app.auth.token","target_key":"jwt.encode","resolution":"exact","method_name":"encode","line":4},
			{"caller_key":"app.auth.token","target_key":"app.auth.(params).update","resolution":"name_only","method_name":"update","arity":1,"receiver_var":"params","line":5},
			{"caller_key":"app.auth.fetch","target_key":"requests.get","resolution":"exact","method_name":"get","line":9}]}`), &sites); err != nil {
		t.Fatal(err)
	}
	plan, rejected := appreach.NewPlan(appreach.Request{
		SchemaVersion: appreach.RequestSchemaVersion, Dependencies: deps, CallSites: &sites,
		IncludeCallChains: true, MaxChainsPerFinding: 1,
	}, appreach.DefaultLimits)
	if rejected != nil {
		t.Fatalf("rejected: %s", rejected.InfoMessage)
	}
	const (
		encode = "jwt.api_jwt.(PyJWT).encode"
		sign   = "cryptography.hazmat.primitives.asymmetric.rsa.(RSAPrivateKey).sign"
		idna   = "idna.core.encode"
		update = "cryptography.hazmat.primitives.hashes.(Hash).update"
		get    = "requests.api.get"
		send   = "requests.sessions.(Session).request"
	)
	loaded := make(map[appreach.ComponentKey]appreach.Component)
	for _, d := range deps {
		key := appreach.ComponentKey{Purl: d.Purl, Version: d.Version}
		switch d.Purl {
		case "pkg:pypi/pyjwt":
			loaded[key] = pythonServedFragment(d.Purl, d.Version, []string{encode},
				[]gf.ExternalCall{pyCall(encode, sign, gf.ResolutionExact, "sign", 20), pyCall(encode, idna, gf.ResolutionExact, "encode", 21)},
				map[string][]string{"jwt.encode": {encode}},
				[]gf.CryptoOperation{pyOp(encode, "jwt/api_jwt.py", 19, "f-jwt")})
		case "pkg:pypi/cryptography":
			loaded[key] = pythonServedFragment(d.Purl, d.Version, []string{sign, update}, nil, nil,
				[]gf.CryptoOperation{
					pyOp(sign, "cryptography/hazmat/primitives/asymmetric/rsa.py", 7, "f-rsa"),
					pyOp(update, "cryptography/hazmat/primitives/hashes.py", 3, "f-hash"),
				})
		case "pkg:pypi/requests":
			request := pyCall(get, "requests.api.(session).request", gf.ResolutionNameOnly, "request", 59)
			request.ReceiverVar = "session"
			loaded[key] = pythonServedFragment(d.Purl, d.Version, []string{get, send}, []gf.ExternalCall{request},
				map[string][]string{"requests.get": {get}},
				[]gf.CryptoOperation{pyOp(send, "requests/sessions.py", 500, "f-tls")})
		case "pkg:pypi/idna":
			loaded[key] = pythonServedFragment(d.Purl, d.Version, []string{idna}, nil, nil,
				[]gf.CryptoOperation{pyOp(idna, "idna/core.py", 3, "f-idna")})
		default:
			loaded[key] = pythonServedFragment(d.Purl, d.Version, nil, nil, nil, nil)
		}
	}
	edges, _ := plan.RequestEdges()
	resp, _, err := plan.Run(context.Background(), loaded, edges, appreach.RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := make(map[string]string)
	for _, d := range resp.Dependencies {
		for _, f := range d.Findings {
			for _, a := range f.CryptographicAssets {
				got[f.FilePath] = a.Reachability + ":" + a.ReachabilityReason
			}
		}
	}
	want := map[string]string{
		"pyjwt@" + versions["pkg:pypi/pyjwt"] + "/jwt/api_jwt.py":                                                 "reachable:",
		"cryptography@" + versions["pkg:pypi/cryptography"] + "/cryptography/hazmat/primitives/asymmetric/rsa.py": "reachable:",
		"idna@" + versions["pkg:pypi/idna"] + "/idna/core.py":                                                     "reachable:",
		"cryptography@" + versions["pkg:pypi/cryptography"] + "/cryptography/hazmat/primitives/hashes.py":         "unreachable:",
		"requests@" + versions["pkg:pypi/requests"] + "/requests/sessions.py":                                     "unknown:unresolved_dispatch",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("verdicts by served path\n got %v\nwant %v", got, want)
	}
}

// A Python dependency installed under markers or with extras names them on
// its findings' dependency_info; one installed unconditionally adds nothing.
// An unpinned declared dependency is listed among the dependencies without
// data, reason unpinned, with its specifier and marker.
func TestMergeApplicationReachability_PythonMarkersAndUnpinned(t *testing.T) {
	closure := &ApplicationClosure{Ecosystem: "python", Resolved: &dependency.ResolveResult{
		Dependencies: []dependency.Dependency{
			{Module: "cryptography", Version: "44.0.2", Markers: []string{`platform_python_implementation != "PyPy"`}},
			{Module: "pyjwt", Version: "2.10.1", Extras: []string{"crypto"}},
			{Module: "idna", Version: "3.10"},
		},
		Unpinned: []dependency.UnpinnedDependency{{Module: "requests", Specifier: ">=2", Marker: `python_version >= "3.9"`, Manifest: "requirements.txt"}},
	}}
	served := func(purl, version, path string) apiclient.ApplicationDependencyAnswer {
		return apiclient.ApplicationDependencyAnswer{Purl: purl, Version: version, InfoCode: "READY", Findings: []apiclient.ApplicationFinding{{
			FilePath: path, Language: "python",
			CryptographicAssets: []apiclient.ApplicationAsset{{
				Asset:        entities.CryptographicAsset{StartLine: 3, Rules: []entities.RuleInfo{{ID: "r"}}},
				Reachability: "unknown", ReachabilityReason: "unresolved_dispatch",
			}},
		}}}
	}
	answer := &apiclient.ApplicationReachability{InfoCode: "READY", Dependencies: []apiclient.ApplicationDependencyAnswer{
		served("pkg:pypi/cryptography", "44.0.2", "cryptography@44.0.2/cryptography/fernet.py"),
		served("pkg:pypi/pyjwt", "2.10.1", "pyjwt@2.10.1/jwt/api_jws.py"),
		served("pkg:pypi/idna", "3.10", "idna@3.10/idna/core.py"),
	}}
	result, outcome := MergeApplicationReachability(&entities.InterimReport{}, &DepScanResult{}, closure, answer)
	AddUnpinned(&outcome, closure)
	got := map[string]entities.DependencyInfo{}
	for _, f := range result.Report.Findings {
		got[f.FilePath] = *f.CryptographicAssets[0].DependencyInfo
	}
	want := map[string]entities.DependencyInfo{
		"cryptography/fernet.py": {Module: "cryptography", Version: "44.0.2", PURL: "pkg:pypi/cryptography@44.0.2", Markers: []string{`platform_python_implementation != "PyPy"`}},
		"jwt/api_jws.py":         {Module: "pyjwt", Version: "2.10.1", PURL: "pkg:pypi/pyjwt@2.10.1", Extras: []string{"crypto"}},
		"idna/core.py":           {Module: "idna", Version: "3.10", PURL: "pkg:pypi/idna@3.10"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dependency_info\n got %+v\nwant %+v", got, want)
	}
	if m := dependencyInfoOf("python", "pkg:pypi/idna", "3.10").Module; m != "idna" {
		t.Errorf("module of a served Python finding without dependency_info = %q, want idna", m)
	}
	if info := dependencyInfoOf("go", "pkg:golang/filippo.io/age", "v1.3.2"); info.Module != "filippo.io/age" || info.PURL != "pkg:golang/filippo.io/age@v1.3.2" {
		t.Errorf("served Go finding without dependency_info = %+v, want module filippo.io/age", info)
	}
	if info := dependencyInfoOf("node", "pkg:npm/%40noble/hashes", "1.3.2"); info.Module != "@noble/hashes" || info.PURL != "pkg:npm/%40noble/hashes@1.3.2" {
		t.Errorf("served npm finding without dependency_info = %+v, want module @noble/hashes", info)
	}
	if info := dependencyInfoOf("rust", "pkg:cargo/aes-gcm", "0.10.3"); info.Module != "aes-gcm" || info.PURL != "pkg:cargo/aes-gcm@0.10.3" {
		t.Errorf("served Cargo finding without dependency_info = %+v, want module aes-gcm", info)
	}
	wantWithout := []DependencyWithout{{Module: "requests", PURL: "pkg:pypi/requests", Reason: "unpinned", Specifier: ">=2", Markers: []string{`python_version >= "3.9"`}}}
	if !reflect.DeepEqual(outcome.DependenciesWithout, wantWithout) || outcome.Dependencies != 4 || outcome.Unknown != 3 {
		t.Errorf("outcome = %+v", outcome)
	}
}

// A dependency scan's request, from a resolved closure to the wire, goes to
// POST /v3/cryptography/reachability/application: a Python lock and a Java
// closure each reach a fake API at that path, and nothing is sent to the
// retired /reachability/project.
func TestApplicationReachability_ClosureRequestReachesApplicationEndpoint(t *testing.T) {
	t.Setenv("VIRTUAL_ENV", "")
	python, err := ResolveApplicationClosure(context.Background(), dependency.NewPythonResolver(), filepath.Join("..", "dependency", "testdata", "python", "uv"), nil)
	if err != nil {
		t.Fatalf("ResolveApplicationClosure: %v", err)
	}
	cases := map[string]*ApplicationClosure{"python lock": python, "java closure": applicationClosureFixture()}
	for name, closure := range cases {
		t.Run(name, func(t *testing.T) {
			var paths []string
			var sent apiclient.ApplicationReachabilityRequest
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.Method+" "+r.URL.Path)
				_ = json.NewDecoder(r.Body).Decode(&sent)
				_, _ = w.Write([]byte(`{"schema_version":"1","info_code":"READY"}`))
			}))
			defer server.Close()

			request, err := closure.Request(&gf.GraphFragmentExport{SchemaVersion: gf.SchemaVersion}, nil, 1)
			if err != nil {
				t.Fatalf("Request: %v", err)
			}
			client := apiclient.NewClientWithHTTPClient(server.URL, "key", server.Client(), apiclient.WithAllowHTTP(true))
			if _, err := client.ApplicationReachability(context.Background(), request); err != nil {
				t.Fatalf("ApplicationReachability: %v", err)
			}
			if want := []string{"POST /v3/cryptography/reachability/application"}; !reflect.DeepEqual(paths, want) {
				t.Errorf("requests = %v, want %v", paths, want)
			}
			if len(sent.Dependencies) != len(request.Dependencies) || len(sent.Dependencies) == 0 {
				t.Errorf("sent %d dependencies, built %d", len(sent.Dependencies), len(request.Dependencies))
			}
		})
	}
}
