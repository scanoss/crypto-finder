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

package scan

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// entryRuleCase is one planted crypto call in an entry_rules fixture and the
// verdict it must get. rootKind and first describe one of its chains: the
// root kind of its first frame and a substring of that frame's name. An empty
// rootKind asks for no chain check.
type entryRuleCase struct {
	id, file, needle string
	reachability     string
	rootKind         callgraph.RootKind
	first            string
}

// entryRulesFixture builds testdata/entry_rules/<dir> with parser and plants
// one finding per case.
func entryRulesFixture(t *testing.T, dir, ecosystem, language string, parser callgraph.Parser, cases []entryRuleCase) entryRootsFixture {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(testFile), "testdata", "entry_rules", dir)
	graph, err := callgraph.NewBuilderForEcosystem(ecosystem, parser).BuildFromDirectories([]callgraph.PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	report := &entities.InterimReport{Tool: entities.ToolInfo{Name: "crypto-finder", Version: "test"}}
	for _, c := range cases {
		line := lineContaining(t, filepath.Join(root, c.file), c.needle)
		report.Findings = append(report.Findings, entities.Finding{
			FilePath: c.file,
			Language: language,
			CryptographicAssets: []entities.CryptographicAsset{{
				FindingID: c.id,
				StartLine: line,
				EndLine:   line,
				Match:     c.needle,
				Rules:     []entities.RuleInfo{{ID: language + ".crypto." + c.id}},
				Metadata:  map[string]string{"assetType": "algorithm"},
			}},
		})
	}
	return entryRootsFixture{root: root, result: &engine.DepScanResult{
		Report:      report,
		CallGraph:   graph,
		Ecosystem:   ecosystem,
		ProjectRoot: root,
	}}
}

// checkEntryRules exports the fixture and checks every case.
func checkEntryRules(t *testing.T, fixture entryRootsFixture, cases []entryRuleCase) {
	t.Helper()
	graphs := exportEntryRoots(t, fixture, 0)
	for _, c := range cases {
		fg, ok := graphs[c.id]
		if !ok {
			t.Errorf("%s: no finding graph", c.id)
			continue
		}
		if fg.Reachability != c.reachability {
			t.Errorf("%s: reachability = %q, want %q (chains %+v)", c.id, fg.Reachability, c.reachability, shortChains(fg))
			continue
		}
		if c.rootKind == "" {
			continue
		}
		found := false
		for _, chain := range fg.CallChains {
			if chain[0].RootKind == string(c.rootKind) && strings.Contains(chain[0].FunctionName, c.first) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: chains = %+v, want one starting at %q as %s", c.id, shortChains(fg), c.first, c.rootKind)
		}
	}
}

// TestExportCallGraph_JavaContainerEntryPoints: methods a Java container calls
// by reflection or lifecycle are entry points, so crypto written directly in
// them is reachable. An annotation counts through a single-type or on-demand
// import or its qualified spelling, and one of the same simple name from
// another package does not. A method nothing calls that no rule recognizes
// stays unreachable.
func TestExportCallGraph_JavaContainerEntryPoints(t *testing.T) {
	t.Parallel()
	cases := []entryRuleCase{
		{
			id: "postconstruct", file: "src/main/java/com/app/boot/KeyWarmup.java", needle: `getInstance("SHA-256")`,
			reachability: graphfrag.ReachabilityReachable, rootKind: callgraph.RootKindFrameworkEntry, first: "KeyWarmup.warmUp",
		},
		{
			id: "bean", file: "src/main/java/com/app/boot/CryptoConfig.java", needle: `getInstance("AES")`,
			reachability: graphfrag.ReachabilityReachable, rootKind: callgraph.RootKindFrameworkEntry, first: "CryptoConfig.sessionKeys",
		},
		{
			id: "servlet", file: "src/main/java/com/app/web/LegacyExportServlet.java", needle: `getInstance("DES`,
			reachability: graphfrag.ReachabilityReachable, rootKind: callgraph.RootKindFrameworkEntry, first: "LegacyExportServlet.doPost",
		},
		{
			id: "websocket", file: "src/main/java/com/app/ws/ChatEndpoint.java", needle: `getInstance("MD5")`,
			reachability: graphfrag.ReachabilityReachable, rootKind: callgraph.RootKindFrameworkEntry, first: "ChatEndpoint.onMessage",
		},
		{
			id: "helper", file: "src/main/java/com/app/ws/AuditFeed.java", needle: `getInstance("SHA-1")`,
			reachability: graphfrag.ReachabilityUnreachable,
		},
		{
			id: "on-demand-import", file: "src/main/java/com/app/jobs/Rotation.java", needle: `getInstance("SHA-384")`,
			reachability: graphfrag.ReachabilityReachable, rootKind: callgraph.RootKindFrameworkEntry, first: "Rotation.rotate",
		},
		{
			id: "qualified-annotation", file: "src/main/java/com/app/jobs/Rotation.java", needle: `getInstance("SHA-224")`,
			reachability: graphfrag.ReachabilityReachable, rootKind: callgraph.RootKindFrameworkEntry, first: "Rotation.onKey",
		},
		// @PostConstruct imported from org.acme.lifecycle, not jakarta.annotation.
		{
			id: "unrelated-annotation", file: "src/main/java/com/app/boot/LocalHooks.java", needle: `getInstance("SHA-512")`,
			reachability: graphfrag.ReachabilityUnreachable,
		},
	}
	checkEntryRules(t, entryRulesFixture(t, "java", "java", "java", callgraph.NewJavaParser(), cases), cases)
}

// TestExportCallGraph_NodeEntryPoints: route handlers, Next.js and NestJS
// handlers, React components reached through JSX, the package entry and
// require.main === module are where JavaScript and TypeScript chains start. A
// function written inline as an argument runs when the call it is passed to
// runs, so crypto in a Promise executor is reached through the function that
// creates the promise. A .get(path, fn) on a receiver no router package
// provides is not a route.
func TestExportCallGraph_NodeEntryPoints(t *testing.T) {
	t.Parallel()
	reachable := graphfrag.ReachabilityReachable
	cases := []entryRuleCase{
		// app.post('/sessions', (req, res) => signSession(..))
		{id: "route-inline", file: "src/security/tokens.ts", needle: `createHash('sha256')`, reachability: reachable, rootKind: callgraph.RootKindFrameworkEntry, first: "server.<anonymous>@8:"},
		// crypto directly in the route's arrow
		{id: "route-own", file: "src/server.ts", needle: `createHash('sha1')`, reachability: reachable, rootKind: callgraph.RootKindFrameworkEntry, first: "server.<anonymous>@12:"},
		// app.get('/export', exportHandler), exportHandler imported
		{id: "route-ref", file: "src/routes/export.ts", needle: `createHash('md5')`, reachability: reachable, rootKind: callgraph.RootKindFrameworkEntry, first: "export.exportHandler"},
		// app.listen(8080, () => warmCache()) at the top of the package entry
		{id: "listen-callback", file: "src/security/tokens.ts", needle: `createHash('sha384')`, reachability: reachable, rootKind: callgraph.RootKindMain, first: "server.<module>"},
		{id: "exported-uncalled", file: "src/security/tokens.ts", needle: `createHash('md4')`, reachability: graphfrag.ReachabilityUnreachable},
		{id: "promise-executor", file: "src/security/tokens.ts", needle: `createHash('ripemd160')`, reachability: reachable, rootKind: callgraph.RootKindNoCallers, first: "tokens.fetchLegacy"},
		// AccountPage renders <Statements/>, which calls avatarUrl
		{id: "jsx", file: "src/lib/avatar.ts", needle: `createHash('md5')`, reachability: reachable, rootKind: callgraph.RootKindFrameworkEntry, first: "AccountPage.AccountPage"},
		{id: "next-route", file: "src/app/api/keys/route.ts", needle: `createHash('sha224')`, reachability: reachable, rootKind: callgraph.RootKindFrameworkEntry, first: "route.POST"},
		{id: "nest", file: "src/keys.controller.ts", needle: `createHash('sha512')`, reachability: reachable, rootKind: callgraph.RootKindFrameworkEntry, first: "KeysController.rotate"},
		{id: "require-main", file: "src/cli.js", needle: `createHash('sha512-256')`, reachability: reachable, rootKind: callgraph.RootKindMain, first: "cli.<module>"},
		{id: "library-export", file: "packages/hashlib/lib/index.js", needle: `createHash('sha3-256')`, reachability: reachable, rootKind: callgraph.RootKindFrameworkEntry, first: "fingerprint"},
		// memo.get('/session', () => ..): memo comes from no router package,
		// so the callback is called by the module that passes it, not a route.
		{id: "not-a-router", file: "src/cache/warm.ts", needle: `createHash('sha512-224')`, reachability: reachable, rootKind: callgraph.RootKindNoCallers, first: "warm.<module>"},
	}
	checkEntryRules(t, entryRulesFixture(t, "node", "node", "typescript", callgraph.NewNodeParser(), cases), cases)
}

// TestExportCallGraph_PythonEntryPoints: Flask and FastAPI routes, Celery
// tasks, click commands, Django views wired in urls.py and class-based view
// methods, a __main__ guard and the project's console scripts are entry
// points, so crypto written directly in them is reachable. A command
// decorator from neither click nor typer is not an entry point.
func TestExportCallGraph_PythonEntryPoints(t *testing.T) {
	t.Parallel()
	reachable := graphfrag.ReachabilityReachable
	framework := callgraph.RootKindFrameworkEntry
	cases := []entryRuleCase{
		{id: "flask", file: "src/shop/app.py", needle: "hashlib.sha1(", reachability: reachable, rootKind: framework, first: "digest"},
		{id: "fastapi", file: "src/shop/api/routes.py", needle: "hashlib.md5(", reachability: reachable, rootKind: framework, first: "health"},
		{id: "apirouter", file: "src/shop/api/routes.py", needle: "hashlib.sha224(", reachability: reachable, rootKind: framework, first: "create_order"},
		{id: "celery", file: "src/shop/tasks.py", needle: "hashlib.sha384(", reachability: reachable, rootKind: framework, first: "reconcile"},
		{id: "orphan", file: "src/shop/tasks.py", needle: "hashlib.sha3_256(", reachability: graphfrag.ReachabilityUnreachable},
		{id: "click", file: "src/shop/commands.py", needle: "hashlib.blake2b(", reachability: reachable, rootKind: framework, first: "export"},
		// @commands.command() where commands comes from the application, not
		// from click or typer.
		{id: "not-click", file: "src/shop/plugins.py", needle: "hashlib.sha3_512(", reachability: graphfrag.ReachabilityUnreachable},
		{id: "django-urls", file: "src/shop/web/views.py", needle: "hashlib.sha256(", reachability: reachable, rootKind: framework, first: "receipt"},
		{id: "django-cbv", file: "src/shop/web/views.py", needle: "hashlib.blake2s(", reachability: reachable, rootKind: framework, first: "RefundView"},
		{id: "main-guard", file: "src/shop/batch.py", needle: "hashlib.shake_128(", reachability: reachable, rootKind: callgraph.RootKindMain, first: "batch.<module>"},
		{id: "console-script", file: "src/shop/cli.py", needle: "hashlib.sha512(", reachability: reachable, rootKind: callgraph.RootKindMain, first: "rotate_keys"},
	}
	checkEntryRules(t, entryRulesFixture(t, "python", "python", "python", callgraph.NewPythonParser(), cases), cases)
}

// TestExportCallGraph_GoEntryPoints: init functions and package variable
// initializers, net/http handlers registered by name, through
// http.HandlerFunc or as a method value, ServeHTTP methods, gRPC service
// methods and cobra command functions are entry points, so crypto written
// directly in them is reachable. A method value is matched on its receiver's
// type, so a method of the same name on another type is not an entry point.
func TestExportCallGraph_GoEntryPoints(t *testing.T) {
	t.Parallel()
	reachable := graphfrag.ReachabilityReachable
	framework := callgraph.RootKindFrameworkEntry
	cases := []entryRuleCase{
		{id: "init", file: "main.go", needle: "sha256.Sum256(", reachability: reachable, rootKind: callgraph.RootKindMain, first: "<init:"},
		{id: "varinit", file: "main.go", needle: "sha256.Sum224(", reachability: reachable, rootKind: callgraph.RootKindMain, first: "<varinit:"},
		{id: "handlefunc", file: "handlers.go", needle: "md5.Sum(", reachability: reachable, rootKind: framework, first: "digest"},
		{id: "handlerfunc", file: "handlers.go", needle: "sha1.Sum(", reachability: reachable, rootKind: framework, first: "legacy"},
		{id: "method-value", file: "handlers.go", needle: "sha512.Sum512(", reachability: reachable, rootKind: framework, first: "sign"},
		// audit.sign has the name of the registered api.sign, but nothing
		// registers an audit.
		{id: "same-name-method", file: "handlers.go", needle: "md5.New()", reachability: graphfrag.ReachabilityUnreachable},
		{id: "servehttp", file: "handlers.go", needle: "hmac.New(", reachability: reachable, rootKind: framework, first: "ServeHTTP"},
		{id: "orphan", file: "handlers.go", needle: "sha512.Sum384(", reachability: graphfrag.ReachabilityUnreachable},
		{id: "grpc", file: "grpc.go", needle: "sha512.Sum512_256(", reachability: reachable, rootKind: framework, first: "Rotate"},
		{id: "cobra", file: "cmd.go", needle: "sha512.Sum512_224(", reachability: reachable, rootKind: framework, first: "runExport"},
	}
	checkEntryRules(t, entryRulesFixture(t, "golang", "go", "go", callgraph.NewGoParser(), cases), cases)
}
