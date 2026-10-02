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

import (
	"os"
	"path/filepath"
	"testing"
)

// grpcRefs parses one Go file and returns the registration refs it records.
func grpcRefs(t *testing.T, src string) []EntryRef {
	t.Helper()
	path := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	analysis, err := NewGoParser().ParseFile(path, "example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	var refs []EntryRef
	for i := range analysis.EntryRefs {
		if analysis.EntryRefs[i].Interface != (FunctionID{}) {
			refs = append(refs, analysis.EntryRefs[i])
		}
	}
	return refs
}

const grpcImports = `package main

import (
	pb "example.com/gen/keys"
	"example.com/gen/other"
)

type impl struct{}
type holder struct{ srv *impl }
`

func TestServerRegistration_ResolvesTheRegisteredValue(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		body string
		want EntryRef
	}{
		"composite literal": {
			body: `func f(s any) { pb.RegisterKeysServer(s, &impl{}) }`,
			want: EntryRef{Function: FunctionID{Package: "example.com/app", Type: "impl"}},
		},
		"new": {
			body: `func f(s any) { pb.RegisterKeysServer(s, new(impl)) }`,
			want: EntryRef{Function: FunctionID{Package: "example.com/app", Type: "impl"}},
		},
		"local variable": {
			body: `func f(s any) { srv := &impl{}; pb.RegisterKeysServer(s, srv) }`,
			want: EntryRef{Function: FunctionID{Package: "example.com/app", Type: "impl"}},
		},
		"typed parameter": {
			body: `func f(s any, srv *impl) { pb.RegisterKeysServer(s, srv) }`,
			want: EntryRef{Function: FunctionID{Package: "example.com/app", Type: "impl"}},
		},
		"typed field": {
			body: `func (h *holder) f(s any) { pb.RegisterKeysServer(s, h.srv) }`,
			want: EntryRef{Function: FunctionID{Package: "example.com/app", Type: "impl"}},
		},
		"imported type": {
			body: `func f(s any, srv *other.Service) { pb.RegisterKeysServer(s, srv) }`,
			want: EntryRef{Function: FunctionID{Package: "example.com/gen/other", Type: "Service"}},
		},
		"constructor": {
			body: `func f(s any) { pb.RegisterKeysServer(s, newImpl()) }`,
			want: EntryRef{Function: FunctionID{Package: "example.com/app", Name: "newImpl"}, Constructor: true},
		},
		"imported constructor": {
			body: `func f(s any) { pb.RegisterKeysServer(s, other.NewService()) }`,
			want: EntryRef{Function: FunctionID{Package: "example.com/gen/other", Name: "NewService"}, Constructor: true},
		},
		"interface-typed parameter": {
			body: `func f(s any, srv pb.KeysServer) { pb.RegisterKeysServer(s, srv) }`,
			want: EntryRef{Function: FunctionID{Package: "example.com/gen/keys", Type: "KeysServer"}, Producers: true},
		},
		"gateway": {
			body: `func f(ctx, mux any) { pb.RegisterKeysHandlerServer(ctx, mux, &impl{}) }`,
			want: EntryRef{Function: FunctionID{Package: "example.com/app", Type: "impl"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			refs := grpcRefs(t, grpcImports+tc.body)
			tc.want.AllExported = true
			tc.want.Interface = FunctionID{Package: "example.com/gen/keys", Type: "KeysServer"}
			tc.want.Kind = RootKindFrameworkEntry
			if len(refs) != 1 || refs[0] != tc.want {
				t.Fatalf("refs = %+v, want [%+v]", refs, tc.want)
			}
		})
	}
}

func TestServerRegistration_UnknownValuesRegisterNothing(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"method call result":  `func f(s any, h *holder) { pb.RegisterKeysServer(s, h.build()) }`,
		"untyped parameter":   `func f(s, srv any) { pb.RegisterKeysServer(s, srv) }`,
		"unknown identifier":  `func f(s any) { pb.RegisterKeysServer(s, missing) }`,
		"single argument":     `func f() { pb.RegisterKeysServer(&impl{}) }`,
		"not a Register call": `func f(s any) { pb.NewKeysServer(s, &impl{}) }`,
		"client":              `func f(s any) { pb.RegisterKeysClient(s, &impl{}) }`,
		"package function":    `func f(s any) { RegisterKeysServer(s, &impl{}) }`,
		"shadowed import":     `func f(s any) { pb := &holder{}; pb.RegisterKeysServer(s, &impl{}) }`,
		"no service name":     `func f(s any) { pb.RegisterServer(s, &impl{}) }`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			refs := grpcRefs(t, grpcImports+body)
			if len(refs) != 0 {
				t.Fatalf("refs = %+v, want none", refs)
			}
		})
	}
}

func TestHasGRPCSignature(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		params []string
		result string
		want   bool
	}{
		"unary":            {[]string{"context.Context", "*pb.Req"}, "(*example.com/gen.Resp, error)", true},
		"server stream":    {[]string{"*pb.Req", "pb.Keys_WatchServer"}, "error", true},
		"bidi stream":      {[]string{"pb.Keys_ChatServer"}, "error", true},
		"plain helper":     {[]string{"[]byte"}, "[]byte", false},
		"no context":       {[]string{"string", "*pb.Req"}, "(*pb.Resp, error)", false},
		"value request":    {[]string{"context.Context", "pb.Req"}, "(*pb.Resp, error)", false},
		"no error":         {[]string{"context.Context", "*pb.Req"}, "(*pb.Resp, int)", false},
		"unqualified base": {[]string{"Server"}, "error", false},
		"other service":    {[]string{"*pb.Req", "pb.Audit_FeedServer"}, "error", false},
		"not a stream":     {[]string{"*pb.Req", "pb.KeysServer"}, "error", false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			decl := &FunctionDecl{ReturnType: tc.result}
			for _, typ := range tc.params {
				decl.Parameters = append(decl.Parameters, FunctionParameter{Type: typ})
			}
			if got := hasGRPCSignature(decl, "Keys"); got != tc.want {
				t.Fatalf("hasGRPCSignature = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestServerRegistration_RegistrarEvidenceInTheFile(t *testing.T) {
	t.Parallel()
	const imports = `package main

import (
	pb "example.com/gen/keys"
	"google.golang.org/grpc"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"example.com/app/boot"
)

type impl struct{}
type holder struct{ gs *grpc.Server }

`
	for name, tc := range map[string]struct {
		body      string
		confirmed bool
		source    FunctionID
		imports   bool
		index     int
	}{
		"grpc.NewServer":    {body: `func f() { gs := grpc.NewServer(); pb.RegisterKeysServer(gs, &impl{}) }`, confirmed: true, imports: true},
		"typed parameter":   {body: `func f(gs *grpc.Server) { pb.RegisterKeysServer(gs, &impl{}) }`, confirmed: true},
		"service registrar": {body: `func f(r grpc.ServiceRegistrar) { pb.RegisterKeysServer(r, &impl{}) }`, confirmed: true},
		"typed field":       {body: `func (h *holder) f() { pb.RegisterKeysServer(h.gs, &impl{}) }`, confirmed: true},
		"gateway mux":       {body: `func f(ctx any) { pb.RegisterKeysHandlerServer(ctx, runtime.NewServeMux(), &impl{}) }`, confirmed: true},
		"untyped":           {body: `func f(s any) { pb.RegisterKeysServer(s, &impl{}) }`, imports: true},
		"other package":     {body: `func f(s *boot.Mux) { pb.RegisterKeysServer(s, &impl{}) }`},
		"result of a function": {
			body:   `func f() { l, s, err := boot.Listen(); pb.RegisterKeysServer(s, &impl{}) }`,
			source: FunctionID{Package: "example.com/app/boot", Name: "Listen"}, index: 1, imports: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			refs := grpcRefs(t, imports+tc.body)
			if len(refs) != 1 || refs[0].GRPCRegistrar != tc.confirmed || refs[0].RegistrarFunc != tc.source || refs[0].RegistrarIndex != tc.index || refs[0].FileImportsGRPC != tc.imports {
				t.Fatalf("refs = %+v, want confirmed=%v source=%v index=%d", refs, tc.confirmed, tc.source, tc.index)
			}
		})
	}
}

func TestRegistrationEvidence_FromTheGraph(t *testing.T) {
	t.Parallel()
	iface := FunctionID{Package: "example.com/gen/keys", Type: "KeysServer"}
	ref := EntryRef{Interface: iface}
	graph := func(decls ...*FunctionDecl) *CallGraph {
		g := &CallGraph{Functions: map[string]*FunctionDecl{}}
		for _, decl := range decls {
			g.Functions[decl.ID.String()] = decl
		}
		return g
	}
	listen := &FunctionDecl{ID: FunctionID{Package: "example.com/app/boot", Name: "Listen"}, ReturnType: "(net.Listener, *google.golang.org/grpc.Server, error)"}
	other := &FunctionDecl{ID: FunctionID{Package: "example.com/app/boot", Name: "Dial"}, ReturnType: "(net.Listener, *net/http.Server, error)"}
	for name, tc := range map[string]struct {
		ref   EntryRef
		graph *CallGraph
		want  bool
	}{
		"nothing":               {ref, graph(), false},
		"interface declared":    {ref, graph(&FunctionDecl{ID: FunctionID{Package: iface.Package, Type: iface.Type, Name: "Rotate"}, OwnerType: goOwnerInterface}), true},
		"generated file":        {ref, graph(&FunctionDecl{ID: FunctionID{Package: iface.Package, Name: "Helper"}, FilePath: "gen/keys/keys.pb.go"}), true},
		"other file":            {ref, graph(&FunctionDecl{ID: FunctionID{Package: iface.Package, Name: "Helper"}, FilePath: "gen/keys/keys.go"}), false},
		"generated elsewhere":   {ref, graph(&FunctionDecl{ID: FunctionID{Package: "example.com/other", Name: "Helper"}, FilePath: "other/x.pb.go"}), false},
		"grpc result":           {EntryRef{Interface: iface, RegistrarFunc: listen.ID, RegistrarIndex: 1}, graph(listen), true},
		"wrong result position": {EntryRef{Interface: iface, RegistrarFunc: listen.ID, RegistrarIndex: 0}, graph(listen), false},
		"other result type":     {EntryRef{Interface: iface, RegistrarFunc: other.ID, RegistrarIndex: 1}, graph(other), false},
		"file imports grpc, helper outside the graph":  {EntryRef{Interface: iface, RegistrarFunc: listen.ID, RegistrarIndex: 1, FileImportsGRPC: true}, graph(), true},
		"file imports grpc, helper declared elsewhere": {EntryRef{Interface: iface, RegistrarFunc: other.ID, RegistrarIndex: 1, FileImportsGRPC: true}, graph(other), false},
		"function not in graph":                        {EntryRef{Interface: iface, RegistrarFunc: listen.ID, RegistrarIndex: 1}, graph(), false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := registrationEvidence(tc.graph, &tc.ref); got != tc.want {
				t.Fatalf("registrationEvidence = %v, want %v", got, tc.want)
			}
		})
	}
}
