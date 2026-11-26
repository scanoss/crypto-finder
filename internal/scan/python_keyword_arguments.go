// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"strings"

	"github.com/scanoss/reach/callgraph"
)

// pythonKeywordParameterType is the declared type of the callee's parameter
// a keyword argument names, or "" when the callee is not in the graph or
// declares no such parameter. A keyword argument's place in the call says
// nothing about which parameter it binds.
func pythonKeywordParameterType(callee *callgraph.FunctionDecl, keyword string) string {
	if callee == nil {
		return ""
	}
	for _, param := range callee.Parameters {
		if param.Name == keyword {
			return strings.TrimSpace(param.Type)
		}
	}
	return ""
}

// argumentText is the argument as the call writes it: a Python keyword
// argument's `name=value`, which the parameter holds as its Keyword and the
// value apart, else the expression.
func (p *callGraphParameter) argumentText() string {
	if p.Keyword != "" {
		return p.Keyword + "=" + p.ArgumentExpression
	}
	return p.ArgumentExpression
}
