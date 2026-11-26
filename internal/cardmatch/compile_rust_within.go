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

import "reflect"

// rustSpecializes reports whether every site the positive of y matches, the
// positive of x matches too, at the same range: y is x with metavariables
// (and `...` arguments) written out. A metavariable both share must stand
// for itself, so the bindings agree at the site. The test is structural and
// conservative: paths, types and other shapes compare equal or not at all.
func rustSpecializes(y, x *RustPattern) bool {
	s := rustSubst{shared: map[string]bool{}, theta: map[string]RustExpr{}}
	yv := map[string]bool{}
	y.binds(yv)
	xv := map[string]bool{}
	x.binds(xv)
	for v := range xv {
		s.shared[v] = yv[v]
	}
	switch {
	case x.Call != nil && y.Call != nil:
		return s.call(x.Call, y.Call)
	case x.Ref != nil && y.Ref != nil:
		return reflect.DeepEqual(x.Ref, y.Ref)
	case x.Binary != nil && y.Binary != nil:
		return s.expr(*x.Binary, *y.Binary)
	}
	return false
}

// rustSubst is the substitution of x's metavariables that rustSpecializes
// builds: theta maps a metavariable of x to the expression of y it stands
// for; a shared one (in both) may stand only for itself.
type rustSubst struct {
	shared map[string]bool
	theta  map[string]RustExpr
}

func (s *rustSubst) call(x, y *RustCall) bool {
	switch {
	case x.Callee != nil && y.Callee != nil:
		if !reflect.DeepEqual(x.Callee, y.Callee) {
			return false
		}
	case x.Receiver != nil && y.Receiver != nil:
		if x.Method != y.Method || !reflect.DeepEqual(x.Turbofish, y.Turbofish) || !s.expr(*x.Receiver, *y.Receiver) {
			return false
		}
	default:
		return false
	}
	return s.args(x.Args, y.Args)
}

// args: y's argument list is one x's matches: x's `...` takes any run of
// y's arguments, y's own `...` only inside one of x's.
func (s *rustSubst) args(xs, ys []RustExpr) bool {
	if len(xs) == 0 {
		return len(ys) == 0
	}
	if xs[0].Kind == RustExprEllipsis {
		for k := 0; k <= len(ys); k++ {
			saved := *s
			saved.theta = cloneTheta(s.theta)
			if s.args(xs[1:], ys[k:]) {
				return true
			}
			*s = saved
		}
		return false
	}
	if len(ys) == 0 || ys[0].Kind == RustExprEllipsis {
		return false
	}
	return s.expr(xs[0], ys[0]) && s.args(xs[1:], ys[1:])
}

// bind substitutes y for x's metavariable v.
func (s *rustSubst) bind(v string, y RustExpr) bool {
	switch {
	case y.Kind == RustExprEllipsis || y.Kind == RustExprDeep:
		return false
	case v == "$_":
		return true
	case s.shared[v]:
		return y.Kind == RustExprVar && y.Var == v
	}
	if old, ok := s.theta[v]; ok {
		return reflect.DeepEqual(old, y)
	}
	s.theta[v] = y
	return true
}

func cloneTheta(m map[string]RustExpr) map[string]RustExpr {
	out := make(map[string]RustExpr, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (s *rustSubst) expr(x, y RustExpr) bool {
	if x.Kind == RustExprVar {
		return s.bind(x.Var, y)
	}
	if x.Kind != y.Kind {
		return false
	}
	if x.Kind == RustExprCall {
		return s.call(x.Call, y.Call)
	}
	if x.Kind == RustExprRef || x.Kind == RustExprField || x.Kind == RustExprTry {
		return x.Mut == y.Mut && x.Field == y.Field && s.expr(*x.Sub, *y.Sub)
	}
	if x.Kind == RustExprBinary {
		return x.Op == y.Op && s.expr(*x.Sub, *y.Sub) && s.expr(*x.Right, *y.Right)
	}
	return reflect.DeepEqual(x, y)
}
