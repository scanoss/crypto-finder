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
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// TestExportCallGraph_RustFrameworkEntryPoints: actix-web route attributes and
// to() handlers, axum method routers, warp filter handlers, tonic service
// impls, poem handlers and poem-openapi operations, Lambda service_fn
// handlers and #[tokio::main]/#[actix_web::main] mains are where Rust chains
// start, so crypto written directly in them is reachable. The same names
// from no framework crate, and a function nothing calls, are not entry
// points.
func TestExportCallGraph_RustFrameworkEntryPoints(t *testing.T) {
	t.Parallel()
	reachable := graphfrag.ReachabilityReachable
	unreachable := graphfrag.ReachabilityUnreachable
	framework := callgraph.RootKindFrameworkEntry
	cases := []entryRuleCase{
		{id: "tokio-main", file: "src/main.rs", needle: `b"tokio-main"`, reachability: reachable, rootKind: callgraph.RootKindMain, first: "main"},
		{id: "actix-main", file: "src/bin/server.rs", needle: `b"actix-main"`, reachability: reachable, rootKind: callgraph.RootKindMain, first: "main"},
		{id: "actix-get", file: "src/actix.rs", needle: `b"actix-get"`, reachability: reachable, rootKind: framework, first: "hash_get"},
		{id: "actix-qualified", file: "src/actix.rs", needle: `b"actix-qualified"`, reachability: reachable, rootKind: framework, first: "sign"},
		{id: "actix-route-to", file: "src/actix.rs", needle: `b"actix-route-to"`, reachability: reachable, rootKind: framework, first: "by_route"},
		{id: "actix-resource-to", file: "src/actix.rs", needle: `b"actix-resource-to"`, reachability: reachable, rootKind: framework, first: "by_resource"},
		{id: "actix-web-to", file: "src/actix.rs", needle: `b"actix-web-to"`, reachability: reachable, rootKind: framework, first: "by_default"},
		{id: "axum-get", file: "src/axum_app.rs", needle: `b"axum-get"`, reachability: reachable, rootKind: framework, first: "list"},
		{id: "axum-chained", file: "src/axum_app.rs", needle: `b"axum-chained-post"`, reachability: reachable, rootKind: framework, first: "create"},
		{id: "axum-routing-path", file: "src/axum_app.rs", needle: `b"axum-routing-delete"`, reachability: reachable, rootKind: framework, first: "remove"},
		{id: "axum-module-handler", file: "src/axum_app.rs", needle: `b"axum-module-handler"`, reachability: reachable, rootKind: framework, first: "health"},
		// app.fallback(not_found), with app bound by a let to Router::new()..
		{id: "axum-fallback", file: "src/axum_app.rs", needle: `b"axum-fallback"`, reachability: reachable, rootKind: framework, first: "not_found"},
		{id: "warp-and-then", file: "src/warp_app.rs", needle: `b"warp-and-then"`, reachability: reachable, rootKind: framework, first: "list_keys"},
		{id: "warp-map", file: "src/warp_app.rs", needle: `b"warp-map"`, reachability: reachable, rootKind: framework, first: "hello"},
		{id: "warp-recover", file: "src/warp_app.rs", needle: `b"warp-recover"`, reachability: reachable, rootKind: framework, first: "recover_err"},
		{id: "tonic", file: "src/tonic_app.rs", needle: `b"tonic-rotate"`, reachability: reachable, rootKind: framework, first: "KeyService"},
		{id: "poem-handler", file: "src/poem_app.rs", needle: `b"poem-handler"`, reachability: reachable, rootKind: framework, first: "hello"},
		{id: "poem-openapi", file: "src/poem_app.rs", needle: `b"poem-openapi"`, reachability: reachable, rootKind: framework, first: "Api"},
		{id: "lambda-runtime", file: "src/lambda_app.rs", needle: `b"lambda-runtime"`, reachability: reachable, rootKind: framework, first: "function_handler"},
		{id: "lambda-http", file: "src/lambda_app.rs", needle: `b"lambda-http"`, reachability: reachable, rootKind: framework, first: "http_handler"},
		// #[get] from a local module; get, service_fn and and_then from no
		// framework crate; async_trait from the async_trait crate.
		{id: "lookalike-attribute", file: "src/lookalike.rs", needle: `b"lookalike-attribute"`, reachability: unreachable},
		{id: "lookalike-get", file: "src/lookalike.rs", needle: `b"lookalike-get"`, reachability: unreachable},
		{id: "lookalike-service-fn", file: "src/lookalike.rs", needle: `b"lookalike-service-fn"`, reachability: unreachable},
		{id: "lookalike-and-then", file: "src/lookalike.rs", needle: `b"lookalike-and-then"`, reachability: unreachable},
		{id: "lookalike-async-trait", file: "src/lookalike.rs", needle: `b"lookalike-async-trait"`, reachability: unreachable},
		{id: "orphan", file: "src/lookalike.rs", needle: `b"orphan"`, reachability: unreachable},
	}
	checkEntryRules(t, entryRulesFixture(t, "rust_frameworks", "rust", "rust", callgraph.NewRustParser(), cases), cases)
}

// TestExportCallGraph_RustRocketEntryPoints: Rocket route, catcher and launch
// attributes are entry points, written bare under the crate root's
// #[macro_use] extern crate rocket or qualified. The #[macro_use] counts from
// main.rs when the package also has a lib.rs, and from a src/bin binary's own
// root. A function no attribute marks and nothing calls stays unreachable.
func TestExportCallGraph_RustRocketEntryPoints(t *testing.T) {
	t.Parallel()
	reachable := graphfrag.ReachabilityReachable
	framework := callgraph.RootKindFrameworkEntry
	cases := []entryRuleCase{
		{id: "rocket-launch", file: "src/main.rs", needle: `b"rocket-launch"`, reachability: reachable, rootKind: framework, first: "rocket"},
		{id: "rocket-macro-use", file: "src/routes.rs", needle: `b"rocket-macro-use"`, reachability: reachable, rootKind: framework, first: "index"},
		{id: "rocket-qualified", file: "src/routes.rs", needle: `body.as_bytes()`, reachability: reachable, rootKind: framework, first: "store"},
		{id: "rocket-catch", file: "src/routes.rs", needle: `b"rocket-catch"`, reachability: reachable, rootKind: framework, first: "not_found"},
		{id: "rocket-bin-macro-use", file: "src/bin/admin.rs", needle: `b"rocket-bin-macro-use"`, reachability: reachable, rootKind: framework, first: "admin"},
		{id: "rocket-unmounted", file: "src/routes.rs", needle: `b"rocket-unmounted"`, reachability: graphfrag.ReachabilityUnreachable},
	}
	checkEntryRules(t, entryRulesFixture(t, "rust_rocket", "rust", "rust", callgraph.NewRustParser(), cases), cases)

	// A package with only src/bin binaries, one file and one directory.
	bins := []entryRuleCase{
		{id: "bins-server", file: "src/bin/server.rs", needle: `b"bins-only-server"`, reachability: reachable, rootKind: framework, first: "index"},
		{id: "bins-gateway", file: "src/bin/gateway/routes.rs", needle: `b"bins-only-gateway"`, reachability: reachable, rootKind: framework, first: "health"},
	}
	checkEntryRules(t, entryRulesFixture(t, "rust_rocket_bins", "rust", "rust", callgraph.NewRustParser(), bins), bins)
}
