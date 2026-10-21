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

package sbomcbom

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestParseSBOM_CycloneDX(t *testing.T) {
	doc, err := ParseSBOM([]byte(`{
	  "bomFormat": "CycloneDX", "specVersion": "1.6",
	  "metadata": {"component": {"name": "acme-api", "version": "4.2.0"}},
	  "components": [
	    {"name": "bcprov-jdk18on", "version": "1.78", "purl": "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78?type=jar",
	     "components": [{"name": "nested", "version": "1.0", "purl": "pkg:npm/nested@1.0"}]},
	    {"name": "vendored-thing"}
	  ]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := &Document{
		Format: FormatCycloneDX, Name: "acme-api", Version: "4.2.0",
		Components: []Component{
			{PURL: "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78?type=jar", Name: "bcprov-jdk18on", Version: "1.78"},
			{PURL: "pkg:npm/nested@1.0", Name: "nested", Version: "1.0"},
		},
		WithoutPURL: 1,
	}
	if !reflect.DeepEqual(doc, want) {
		t.Errorf("got %+v\nwant %+v", doc, want)
	}
}

func TestParseSBOM_SPDXJSON(t *testing.T) {
	doc, err := ParseSBOM([]byte(`{
	  "spdxVersion": "SPDX-2.3", "name": "acme-api",
	  "packages": [
	    {"name": "acme-api"},
	    {"name": "node-forge", "versionInfo": "1.3.1",
	     "externalRefs": [{"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:x"},
	                      {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/node-forge@1.3.1"}]}
	  ]}`))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Format != FormatSPDX || doc.Name != "acme-api" || doc.WithoutPURL != 1 ||
		!reflect.DeepEqual(doc.Components, []Component{{PURL: "pkg:npm/node-forge@1.3.1", Name: "node-forge", Version: "1.3.1"}}) {
		t.Errorf("got %+v", doc)
	}
}

func TestParseSBOM_SPDXTagValue(t *testing.T) {
	doc, err := ParseSBOM([]byte(`SPDXVersion: SPDX-2.3
DocumentName: acme-api

PackageName: acme-api
SPDXID: SPDXRef-root

PackageName: cryptography
PackageVersion: 42.0.5
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/cryptography@42.0.5

PackageName: bcrypt
PackageVersion: 4.1.2
ExternalRef: PACKAGE_MANAGER purl pkg:pypi/bcrypt@4.1.2
`))
	if err != nil {
		t.Fatal(err)
	}
	want := []Component{
		{PURL: "pkg:pypi/cryptography@42.0.5", Name: "cryptography", Version: "42.0.5"},
		{PURL: "pkg:pypi/bcrypt@4.1.2", Name: "bcrypt", Version: "4.1.2"},
	}
	if doc.Format != FormatSPDXTagValue || doc.Name != "acme-api" || doc.WithoutPURL != 1 || !reflect.DeepEqual(doc.Components, want) {
		t.Errorf("got %+v", doc)
	}
}

func TestParseSBOM_RejectsOtherDocuments(t *testing.T) {
	for _, in := range []string{`{"name": "package.json"}`, `<bom/>`, ``} {
		if _, err := ParseSBOM([]byte(in)); !errors.Is(err, ErrUnknownFormat) {
			t.Errorf("%q: err %v, want ErrUnknownFormat", in, err)
		}
	}
}

// fakeAPI answers /v3/cryptography/reachability/component the way the
// production API does for the purls in answers, and records what it was asked.
type fakeAPI struct {
	mu      sync.Mutex
	asked   []string
	answers map[string]string
	status  int
}

func (f *fakeAPI) serve(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Purl, Requirement string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		f.mu.Lock()
		f.asked = append(f.asked, req.Purl+"@"+req.Requirement)
		f.mu.Unlock()
		if f.status != 0 {
			w.WriteHeader(f.status)
			return
		}
		body, ok := f.answers[req.Purl+"@"+req.Requirement]
		if !ok {
			body = `{"info_code":"COMPONENT_NOT_FOUND"}`
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server.URL
}

const bcprovAnswer = `{"rules_version":"v1.31.0","info_code":"READY","data":[{"purl":"pkg:maven/org.bouncycastle/bcprov-jdk18on","version":"1.78",
  "findings":[{"file_path":"org/bouncycastle/crypto/engines/AESEngine.java","language":"java","cryptographic_assets":[
    {"finding_id":"a1","match":"new AESEngine()","source":"direct","start_line":92,"end_line":92,
     "metadata":{"assetType":"algorithm","algorithmName":"AES","algorithmFamily":"AES","algorithmPrimitive":"block-cipher","algorithmParameterSetIdentifier":"256"},
     "rules":[{"id":"bc.aes","message":"AES","severity":"INFO"}]},
    {"finding_id":"a2","match":"new RSAEngine()","source":"direct","start_line":40,"end_line":40,
     "metadata":{"assetType":"algorithm","algorithmName":"RSA","algorithmFamily":"RSA","algorithmPrimitive":"pke"},
     "rules":[{"id":"bc.rsa","message":"RSA","severity":"INFO"}]}]}]}]}`

const lodashAnswer = `{"rules_version":"v1.31.0","info_code":"READY","data":[{"purl":"pkg:npm/lodash","version":"4.17.21","findings":[]}]}`

func TestGenerate_BuildsOneCBOMFromTheMinedFindings(t *testing.T) {
	api := &fakeAPI{answers: map[string]string{
		"pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78": bcprovAnswer,
		"pkg:npm/lodash@4.17.21":                         lodashAnswer,
		"pkg:npm/internal-telemetry@0.4.2":               `{"info_code":"COMPONENT_NOT_FOUND"}`,
	}}
	doc := &Document{Name: "acme-api", Version: "4.2.0", Components: []Component{
		{PURL: "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78?type=jar"},
		{PURL: "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78"},
		{PURL: "pkg:npm/lodash@4.17.21"},
		{PURL: "pkg:npm/internal-telemetry@0.4.2"},
		{PURL: "pkg:npm/no-version"},
	}}

	res, err := Generate(context.Background(), doc, Options{APIURL: api.serve(t), APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}

	const bcRef = "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78"
	wantResults := []ComponentResult{
		{PURL: doc.Components[0].PURL, Status: StatusCrypto, InfoCode: "READY", Ref: bcRef, ServedVersion: "1.78"},
		{PURL: doc.Components[1].PURL, Status: StatusCrypto, InfoCode: "READY", Ref: bcRef, ServedVersion: "1.78"},
		{PURL: "pkg:npm/lodash@4.17.21", Status: StatusNoCrypto, InfoCode: "READY", ServedVersion: "4.17.21"},
		{PURL: "pkg:npm/internal-telemetry@0.4.2", Status: StatusNotMined, InfoCode: "COMPONENT_NOT_FOUND"},
		{PURL: "pkg:npm/no-version", Status: StatusUnsupported},
	}
	if !reflect.DeepEqual(res.Components, wantResults) {
		t.Errorf("components:\n got %+v\nwant %+v", res.Components, wantResults)
	}
	if len(api.asked) != 3 {
		t.Errorf("asked %v; want one lookup per distinct purl and version, none for an entry without a version", api.asked)
	}
	if res.RulesVersion != "v1.31.0" {
		t.Errorf("rules version %q", res.RulesVersion)
	}

	bom := res.BOM
	if bom.SpecVersion != cdx.SpecVersion1_7 || bom.Metadata.Component == nil || bom.Metadata.Component.Name != "acme-api" {
		t.Fatalf("spec %v, subject %+v", bom.SpecVersion, bom.Metadata.Component)
	}
	assets := map[string]string{}
	var libraries []string
	for _, c := range *bom.Components {
		if c.Type == cdx.ComponentTypeLibrary {
			libraries = append(libraries, c.PackageURL)
			continue
		}
		assets[c.BOMRef] = c.Name
	}
	if !reflect.DeepEqual(libraries, []string{bcRef}) {
		t.Errorf("libraries %v; only a component with crypto belongs in the CBOM", libraries)
	}
	if bom.Dependencies == nil || len(*bom.Dependencies) != 1 {
		t.Fatalf("dependencies %+v", bom.Dependencies)
	}
	linked := make([]string, 0, 2)
	for _, ref := range *(*bom.Dependencies)[0].Dependencies {
		linked = append(linked, assets[ref])
	}
	sort.Strings(linked)
	if !reflect.DeepEqual(linked, []string{"AES", "RSA"}) {
		t.Errorf("bouncycastle depends on %v, want AES and RSA", linked)
	}
}

func TestGenerate_LeavesOutAComponentWhoseFindingsFailValidation(t *testing.T) {
	const badPadding = `{"rules_version":"v1","info_code":"READY","data":[{"version":"2.0.0","findings":[{"file_path":"Rsa.java","language":"java","cryptographic_assets":[
	  {"start_line":1,"end_line":1,"match":"Cipher.getInstance(x)",
	   "metadata":{"assetType":"algorithm","algorithmName":"RSA","algorithmFamily":"RSA","algorithmPrimitive":"pke","algorithmPadding":"NotAPadding"},
	   "rules":[{"id":"jca.rsa"}]}]}]}]}`
	api := &fakeAPI{answers: map[string]string{
		"pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78": bcprovAnswer,
		"pkg:maven/com.example/broken@2.0.0":             badPadding,
	}}
	doc := &Document{Components: []Component{
		{PURL: "pkg:maven/com.example/broken@2.0.0"},
		{PURL: "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78"},
	}}
	res, err := Generate(context.Background(), doc, Options{APIURL: api.serve(t), APIKey: "k"})
	if err != nil {
		t.Fatalf("one component's findings sank the CBOM: %v", err)
	}
	if res.Components[0].Status != StatusFailed || res.Components[1].Status != StatusCrypto {
		t.Errorf("statuses %q, %q; want failed, crypto", res.Components[0].Status, res.Components[1].Status)
	}
	if len(*res.BOM.Dependencies) != 1 || (*res.BOM.Dependencies)[0].Ref != "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78" {
		t.Errorf("dependencies %+v; want only bouncycastle", *res.BOM.Dependencies)
	}
}

func TestGenerate_TwoVersionsServedTheSameReleaseShareItsFindings(t *testing.T) {
	api := &fakeAPI{answers: map[string]string{
		"pkg:maven/org.bouncycastle/bcprov-jdk18on@1.77": bcprovAnswer,
		"pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78": bcprovAnswer,
	}}
	doc := &Document{Components: []Component{
		{PURL: "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.77"},
		{PURL: "pkg:maven/org.bouncycastle/bcprov-jdk18on", Version: "1.78"},
	}}
	res, err := Generate(context.Background(), doc, Options{APIURL: api.serve(t), APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Components {
		if c.Ref != "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78" {
			t.Errorf("%s: ref %q, want the served release", c.PURL, c.Ref)
		}
	}
	for _, c := range *res.BOM.Components {
		if c.Evidence != nil && c.Evidence.Occurrences != nil && len(*c.Evidence.Occurrences) != 1 {
			t.Errorf("%s has %d occurrences, want 1: the shared findings went in twice", c.Name, len(*c.Evidence.Occurrences))
		}
	}
}

func TestGenerate_DoesNotRetryAClientError(t *testing.T) {
	api := &fakeAPI{status: http.StatusTooManyRequests}
	doc := &Document{Components: []Component{{PURL: "pkg:npm/a@1.0.0"}}}
	res, err := Generate(context.Background(), doc, Options{APIURL: api.serve(t), APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Components[0].Status != StatusFailed || len(api.asked) != 1 {
		t.Errorf("status %q after %d calls; want failed after one call", res.Components[0].Status, len(api.asked))
	}
}

func TestGenerate_RefusedKeyFailsTheRun(t *testing.T) {
	api := &fakeAPI{status: http.StatusUnauthorized}
	doc := &Document{Components: []Component{{PURL: "pkg:npm/a@1.0.0"}, {PURL: "pkg:npm/b@1.0.0"}}}
	_, err := Generate(context.Background(), doc, Options{APIURL: api.serve(t), APIKey: "bad"})
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("err %v, want ErrAccessDenied", err)
	}
}

func TestGenerate_RetriesATransientFailureOnce(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(lodashAnswer))
	}))
	t.Cleanup(server.Close)
	doc := &Document{Components: []Component{{PURL: "pkg:npm/lodash@4.17.21"}}}
	res, err := Generate(context.Background(), doc, Options{APIURL: server.URL, APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Components[0].Status != StatusNoCrypto || calls.Load() != 2 {
		t.Errorf("status %q after %d calls; want no-crypto after one retry", res.Components[0].Status, calls.Load())
	}
}

func TestGenerate_ServerErrorMarksTheComponentFailed(t *testing.T) {
	api := &fakeAPI{status: http.StatusBadGateway}
	doc := &Document{Components: []Component{{PURL: "pkg:npm/a@1.0.0"}}}
	res, err := Generate(context.Background(), doc, Options{APIURL: api.serve(t), APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Components[0].Status != StatusFailed || res.Components[0].Problem == "" || len(api.asked) != 2 {
		t.Errorf("status %q, problem %q after %d calls; want failed with a reason after one retry", res.Components[0].Status, res.Components[0].Problem, len(api.asked))
	}
}

func TestGenerate_CapsDistinctComponents(t *testing.T) {
	api := &fakeAPI{}
	doc := &Document{Components: []Component{{PURL: "pkg:npm/a@1.0.0"}, {PURL: "pkg:npm/a@1.0.0?x=y"}, {PURL: "pkg:npm/b@1.0.0"}}}
	if _, err := Generate(context.Background(), doc, Options{APIURL: api.serve(t), MaxComponents: 1}); !errors.Is(err, ErrTooManyComponents) {
		t.Errorf("err %v, want ErrTooManyComponents", err)
	}
	if len(api.asked) != 0 {
		t.Errorf("asked %v before refusing the SBOM", api.asked)
	}
	if _, err := Generate(context.Background(), doc, Options{APIURL: api.serve(t), MaxComponents: 2}); err != nil {
		t.Errorf("two distinct components under a cap of two: %v", err)
	}
}
