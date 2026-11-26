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

package cardmatch

import (
	"strings"
	"testing"
)

// cppShow prints an expression read by the C++ reader as a compact tree.
func cppShow(e *CExpr) string {
	list := func(xs []CExpr, sep string) string {
		parts := make([]string, len(xs))
		for i := range xs {
			parts[i] = cppShow(&xs[i])
		}
		return strings.Join(parts, sep)
	}
	switch e.Kind {
	case CExprIdent:
		return e.Name
	case CExprMetavar:
		return e.Var
	case CExprInt, CExprFloat, CExprChar:
		return e.Text
	case CExprString:
		return `"` + e.Text + `"`
	case CExprEllipsis:
		return "..."
	case CExprScoped:
		return "scoped(" + e.Op + list(e.Args, " :: ") + ")"
	case CExprTemplate:
		return cppShow(e.Sub) + "<" + list(e.Args, ", ") + ">"
	case CExprType:
		return "type(" + e.Text + ")"
	case CExprNew:
		return "new(" + cppShow(e.Sub) + " " + e.Op + list(e.Args, ", ") + ")"
	case CExprCall:
		return "call" + e.Op + "(" + cppShow(e.Callee) + "; " + list(e.Args, ", ") + ")"
	case CExprMember:
		return "member(" + cppShow(e.Sub) + " " + e.Op + " " + e.Name + ")"
	case CExprUnary:
		return e.Op + cppShow(e.Sub)
	case CExprBinary:
		return "(" + list(e.Args, " "+e.Op+" ") + ")"
	}
	return e.Kind
}

// The C++ reader reads qualified names, templates, new and brace
// initialization, and their spans; the C reader still reads none of them.
func TestCPPReader(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"seal::EncryptionParameters(seal::scheme_type::ckks)", "call(scoped(seal :: EncryptionParameters); scoped(seal :: scheme_type :: ckks))"},
		{"::f(x)", "call(scoped(::f); x)"},
		{"libsnark::gen<ppT>(cs)", "call(scoped(libsnark :: gen<ppT>); cs)"},
		{"std::make_unique<Botan::TLS::Server>(a, b)", "call(scoped(std :: make_unique<scoped(Botan :: TLS :: Server)>); a, b)"},
		{"f<std::vector<int>>(v)", "call(f<scoped(std :: vector<int>)>; v)"},
		{"f<const char *, 3>(v)", "call(f<type(const char *), 3>; v)"},
		{"a < b", "(a < b)"},
		{"g(a < b, c > d)", "call(g; (a < b), (c > d))"},
		{"x->foo(1)", "call(member(x -> foo); 1)"},
		{"obj.header().algo(HS256)", "call(member(call(member(obj . header); ) . algo); HS256)"},
		{"c.createCipher(new CipherKey(\"aes\", p))", "call(member(c . createCipher); new(CipherKey (\"aes\", p))"},
		{"f(new T, oqs::KEM{\"ML-KEM\"})", "call(f; new(T ), new(scoped(oqs :: KEM) {\"ML-KEM\"))"},
		{"A::B<C>::foo(9)", "call(scoped(A :: B<C> :: foo); 9)"},
		{"SHA256()(x)", "call(call(SHA256; ); x)"},
	} {
		e, ok := readCPPExpr(tc.text, false)
		if !ok {
			t.Errorf("%s: unreadable", tc.text)
			continue
		}
		if got := cppShow(e); got != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.text, got, tc.want)
		}
		if e.Start != 0 || e.End != len(tc.text) {
			t.Errorf("%s: span %d-%d", tc.text, e.Start, e.End)
		}
	}
	for _, text := range []string{"a::b(x)", "f<T>(x)", "new T(x)", "T{1}"} {
		if e, ok := readCExpr(text, false); ok && e.Kind == CExprCall {
			t.Errorf("C reads %s as a call", text)
		}
	}
	for _, text := range []string{"x.template f<int>()", "a::operator==(b)", "new (buf) T(x)", "a::~a()"} {
		if _, ok := readCPPExpr(text, false); ok {
			t.Errorf("C++ reads %s", text)
		}
	}
}

// A pattern reads metavariables in a qualified name, a template argument and
// a member name.
func TestCPPReaderPattern(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"$C::init_public_params()", "call(scoped($C :: init_public_params); )"},
		{"Poco::HMACEngine<$T>(...)", "call(scoped(Poco :: HMACEngine<$T>); ...)"},
		{"$X.$M(...)", "call(member($X . $M); ...)"},
		{"jwt::algorithm::$A{...}", "new(scoped(jwt :: algorithm :: $A) {...)"},
		{"jwt::decode(..., verify(false), ...)", "call(scoped(jwt :: decode); ..., call(verify; false), ...)"},
	} {
		e, ok := readCPPExpr(tc.text, true)
		if !ok {
			t.Errorf("%s: unreadable", tc.text)
			continue
		}
		if got := cppShow(e); got != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.text, got, tc.want)
		}
	}
}

// A C++ cast whose type is qualified reads as a cast.
func TestCPPReaderCast(t *testing.T) {
	e, ok := readCPPExpr("hash.Update((const CryptoPP::byte*)message.data(), message.size())", false)
	if !ok || e.Args[0].Kind != CExprCast || e.Args[0].Name != "const CryptoPP :: byte *" {
		t.Fatalf("%v %+v", ok, e)
	}
	if e, ok := readCPPExpr("(a::b)(x)", false); !ok || e.Kind != CExprCast {
		t.Errorf("(a::b)(x): %v %v", ok, e)
	}
}

// A site whose text ends at `new` (a macro or a cut span) is unreadable, not a
// panic: the C++ reader must not read past the last token.
func TestReadCPPExprNewAtEnd(t *testing.T) {
	for _, text := range []string{"new", "x = new", "f(new"} {
		if _, ok := readCPPExpr(text, false); ok {
			t.Errorf("readCPPExpr(%q) read it", text)
		}
	}
	if _, ok := readCPPDecl("T *p = new", false); ok {
		t.Error("readCPPDecl read a declaration ending at new")
	}
}
