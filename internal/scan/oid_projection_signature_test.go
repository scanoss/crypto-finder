package scan

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/oid"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// These assignments make every exported OID projection require the prepared
// type-state; an InterimReport cannot satisfy these signatures.
var (
	_ func(string, string, *engine.DepScanResult, *oid.ResolvedReport) error         = ExportCallGraph
	_ func(string, string, *engine.DepScanResult, *oid.ResolvedReport) error         = ExportGraphFragment
	_ func(*engine.DepScanResult, *oid.ResolvedReport) graphfrag.GraphFragmentExport = BuildGraphFragmentExport
	_ func(*oid.ResolvedReport, graphfrag.Fragment) graphfrag.GraphFragmentExport    = BuildAnnotateExport
)

func TestPreparedGraphProjectionsDoNotRestoreRejectedOIDClaims(t *testing.T) {
	raw := &entities.InterimReport{Findings: []entities.Finding{{CryptographicAssets: []entities.CryptographicAsset{{
		OID: "1.2.840.113549.2", Metadata: map[string]string{
			"assetType": "algorithm", "algorithmName": "HMAC-SHA-256", "algorithmFamily": "HMAC", "algorithmPrimitive": "mac",
		},
	}}}}}
	prepared, err := oid.NewDefaultResolver().PrepareReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	resolved := prepared.ReportClone()
	result := &engine.DepScanResult{}
	fragment := BuildGraphFragmentExport(result, resolved)
	if len(fragment.CryptoAnnotations) > 0 && fragment.CryptoAnnotations[0].OID != "" {
		t.Fatalf("graph fragment restored rejected OID: %#v", fragment.CryptoAnnotations)
	}
	annotation := BuildAnnotateExport(resolved, graphfrag.Fragment{})
	if len(annotation.CryptoAnnotations) != 1 || annotation.CryptoAnnotations[0].OID != "" {
		t.Fatalf("annotation restored rejected OID: %#v", annotation.CryptoAnnotations)
	}
}

func TestProductionResolvedReportsNeverEscapeAsInterimReports(t *testing.T) {
	sources, err := productionGoSources(filepath.Clean(".."))
	if err != nil {
		t.Fatalf("read production Go files: %v", err)
	}
	violations, err := checkResolvedProjectionInvariant(sources)
	if err != nil {
		t.Fatalf("inspect production Go files: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("resolved-report boundary violations:\n%s", strings.Join(violations, "\n"))
	}
}

func productionGoSources(root string) (map[string]string, error) {
	sources := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sources[path] = string(data)
		return nil
	})
	return sources, err
}

func localImportNames(file *ast.File) map[string]string {
	imports := make(map[string]string, len(file.Imports))
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		name := filepath.Base(path)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		imports[path] = name
	}
	return imports
}

func fieldListContains(fields *ast.FieldList, packageName, typeName string) bool {
	for _, field := range fields.List {
		if isNamedType(field.Type, packageName, typeName) {
			return true
		}
	}
	return false
}

func unwrapExpression(expression ast.Expr) ast.Expr {
	for {
		switch value := expression.(type) {
		case *ast.ParenExpr:
			expression = value.X
		case *ast.IndexExpr:
			expression = value.X
		case *ast.IndexListExpr:
			expression = value.X
		default:
			return expression
		}
	}
}

func isNamedType(expression ast.Expr, packageName, typeName string) bool {
	expression = unwrapExpression(expression)
	for {
		pointer, ok := expression.(*ast.StarExpr)
		if !ok {
			break
		}
		expression = unwrapExpression(pointer.X)
	}
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != typeName {
		return false
	}
	identifier, ok := unwrapExpression(selector.X).(*ast.Ident)
	return ok && identifier.Name == packageName
}

func calledName(expression ast.Expr) string {
	expression = unwrapExpression(expression)
	if selector, ok := expression.(*ast.SelectorExpr); ok {
		return selector.Sel.Name
	}
	if identifier, ok := expression.(*ast.Ident); ok {
		return identifier.Name
	}
	return ""
}

func TestResolvedProjectionInvariantMutationMatrix(t *testing.T) {
	cases := []struct {
		name          string
		source        string
		wantViolation bool
	}{
		{
			name: "allows narrowed findings helper",
			source: `package scan
import (
 "github.com/scanoss/crypto-finder/internal/entities"
 "github.com/scanoss/crypto-finder/internal/oid"
)
func entry(report *oid.ResolvedReport) { project(report.Findings) }
func project(findings []entities.Finding) { _ = len(findings) }`,
		},
		{
			name: "allows unreachable raw pre-prepare helper",
			source: `package scan
import (
 "github.com/scanoss/crypto-finder/internal/entities"
 "github.com/scanoss/crypto-finder/internal/oid"
)
func entry(report *oid.ResolvedReport) { project(report.Findings) }
func project(findings []entities.Finding) { _ = len(findings) }
func rawPrePrepare() { _ = &entities.InterimReport{} }`,
		},
		{
			name: "rejects renamed helper raw reconstruction",
			source: `package scan
import (
 "github.com/scanoss/crypto-finder/internal/entities"
 "github.com/scanoss/crypto-finder/internal/oid"
)
func entry(report *oid.ResolvedReport) { renamed(report.Findings) }
func renamed(findings []entities.Finding) { _ = &entities.InterimReport{Findings: findings} }`,
			wantViolation: true,
		},
		{
			name: "rejects accessor chain",
			source: `package scan
import (
 "github.com/scanoss/crypto-finder/internal/entities"
 "github.com/scanoss/crypto-finder/internal/oid"
)
func entry(report *oid.ResolvedReport) { relay(report.Findings) }
func relay(findings []entities.Finding) { allocate(findings) }
func allocate(findings []entities.Finding) { _ = new(entities.InterimReport); _ = findings }`,
			wantViolation: true,
		},
		{
			name: "rejects field by field reconstruction",
			source: `package scan
import (
 "github.com/scanoss/crypto-finder/internal/entities"
 "github.com/scanoss/crypto-finder/internal/oid"
)
func entry(report *oid.ResolvedReport) { rebuild(report.Findings) }
func rebuild(findings []entities.Finding) { var raw entities.InterimReport; raw.Findings = findings }`,
			wantViolation: true,
		},
		{
			name: "rejects returned raw exposure",
			source: `package scan
import (
 "github.com/scanoss/crypto-finder/internal/entities"
 "github.com/scanoss/crypto-finder/internal/oid"
)
func entry(report *oid.ResolvedReport) { _ = expose(report.Findings) }
func expose(findings []entities.Finding) *entities.InterimReport { return &entities.InterimReport{Findings: findings} }`,
			wantViolation: true,
		},
		{
			name: "rejects aliased imports",
			source: `package scan
import (
 e "github.com/scanoss/crypto-finder/internal/entities"
 o "github.com/scanoss/crypto-finder/internal/oid"
)
func entry(report *o.ResolvedReport) { raw(report.Findings) }
func raw(findings []e.Finding) { _ = &e.InterimReport{Findings: findings} }`,
			wantViolation: true,
		},
		{
			name: "rejects function literal",
			source: `package scan
import (
 "github.com/scanoss/crypto-finder/internal/entities"
 "github.com/scanoss/crypto-finder/internal/oid"
)
func entry(report *oid.ResolvedReport) { project := func(findings []entities.Finding) { _ = &entities.InterimReport{Findings: findings} }; project(report.Findings) }`,
			wantViolation: true,
		},
		{
			name: "rejects wrapped occurrence key mutation",
			source: `package scan
import (
 "github.com/scanoss/crypto-finder/internal/engine"
 "github.com/scanoss/crypto-finder/internal/oid"
)
func entry(report *oid.ResolvedReport, result *engine.DepScanResult) { _ = report.Findings; wrapped(result) }
func wrapped(result *engine.DepScanResult) { AssignOccurrenceKeys(result) }`,
			wantViolation: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := checkResolvedProjectionInvariant(map[string]string{"synthetic.go": tt.source})
			if err != nil {
				t.Fatal(err)
			}
			if got := len(violations) > 0; got != tt.wantViolation {
				t.Fatalf("violations = %v, want violation %t", violations, tt.wantViolation)
			}
		})
	}
}

type projectionFunction struct {
	name        string
	file        string
	packagePath string
	imports     map[string]string
	signature   *ast.FuncType
	body        *ast.BlockStmt
	receiver    string
	closure     *lexicalScope
}

// projectionProvenance distinguishes report payload from values merely derived
// from it. The invariant must fail closed for transported Findings data, but a
// file path, line, object id, or map key can only select/control structure.
type projectionProvenance uint8

const (
	projectionNone projectionProvenance = iota
	projectionSelector
	projectionStructural
	projectionPayload
)

func joinProjectionProvenance(left, right projectionProvenance) projectionProvenance {
	if left > right {
		return left
	}
	return right
}

func isProjectionPayload(state projectionProvenance) bool { return state == projectionPayload }

func scalarProjectionField(name string) bool {
	switch strings.ToLower(name) {
	case "id", "filepath", "file", "path", "line", "startline", "endline", "column", "startcol", "endcol", "objectvar", "parentvar", "receivervar", "assignedvar", "chainid", "supportingid":
		return true
	default:
		return false
	}
}

// lexicalScope models only the static facts this structural checker owns. A
// present binding is intentionally different from a binding with no known
// receiver: an unknown local named like an import still shadows that import.
type lexicalBinding struct {
	present    bool
	receiver   string
	alias      ast.Expr
	provenance projectionProvenance
}

type lexicalScope struct {
	parent   *lexicalScope
	bindings map[string]lexicalBinding
}

type lexicalSnapshot struct {
	bindings map[string]lexicalBinding
}

func newLexicalScope(parent *lexicalScope) *lexicalScope {
	return &lexicalScope{parent: parent, bindings: make(map[string]lexicalBinding)}
}

func (scope *lexicalScope) lookup(name string) (lexicalBinding, bool) {
	for current := scope; current != nil; current = current.parent {
		if binding, ok := current.bindings[name]; ok {
			return binding, true
		}
	}
	return lexicalBinding{}, false
}

func (scope *lexicalScope) assign(name string, binding lexicalBinding) bool {
	for current := scope; current != nil; current = current.parent {
		if _, ok := current.bindings[name]; ok {
			current.bindings[name] = binding
			return true
		}
	}
	return false
}

func (scope *lexicalScope) clone() *lexicalScope {
	if scope == nil {
		return nil
	}
	clone := newLexicalScope(scope.parent.clone())
	for name, binding := range scope.bindings {
		clone.bindings[name] = binding
	}
	return clone
}

func equivalentLexicalBinding(left, right lexicalBinding) bool {
	return left.present == right.present && left.receiver == right.receiver && left.alias == right.alias && left.provenance == right.provenance
}

// mergeControlOutcomes retains a receiver type only when every conservative
// outcome agrees. A divergent assignment is still a visible local, but its
// receiver becomes unknown so method-shaped dispatch fails closed.
func mergeControlOutcomes(scope *lexicalScope, outcomes ...*lexicalScope) {
	base := scope.snapshot()
	for name, original := range base.bindings {
		merged := original
		provenance := original.provenance
		equal := true
		for _, outcome := range outcomes {
			candidate, ok := outcome.lookup(name)
			if !ok {
				equal = false
				continue
			}
			provenance = joinProjectionProvenance(provenance, candidate.provenance)
			if !equivalentLexicalBinding(merged, candidate) {
				equal = false
			}
		}
		if !equal {
			merged = lexicalBinding{present: true, provenance: provenance}
		}
		scope.assign(name, merged)
	}
}

func (scope *lexicalScope) snapshot() lexicalSnapshot {
	bindings := make(map[string]lexicalBinding)
	chain := make([]*lexicalScope, 0, 8)
	for current := scope; current != nil; current = current.parent {
		chain = append(chain, current)
	}
	for index := len(chain) - 1; index >= 0; index-- {
		for name, binding := range chain[index].bindings {
			bindings[name] = binding
		}
	}
	return lexicalSnapshot{bindings: bindings}
}

func (snapshot lexicalSnapshot) receiver(name string) (string, bool) {
	binding, ok := snapshot.bindings[name]
	return binding.receiver, ok && binding.present
}

func (snapshot lexicalSnapshot) aliases() map[string]ast.Expr {
	aliases := make(map[string]ast.Expr)
	for name, binding := range snapshot.bindings {
		if binding.alias != nil {
			aliases[name] = binding.alias
		}
	}
	return aliases
}

func (snapshot lexicalSnapshot) present(name string) bool {
	binding, ok := snapshot.bindings[name]
	return ok && binding.present
}

func (snapshot lexicalSnapshot) expressionProvenance(expression ast.Expr) projectionProvenance {
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			break
		}
		expression = parenthesized.X
	}
	switch value := expression.(type) {
	case *ast.Ident:
		return snapshot.bindings[value.Name].provenance
	case *ast.SelectorExpr:
		if identifier, ok := unwrapExpression(value.X).(*ast.Ident); ok && strings.HasSuffix(snapshot.bindings[identifier.Name].receiver, "/oid:ResolvedReport") {
			if value.Sel.Name == "Findings" {
				return projectionPayload
			}
			return projectionSelector
		}
		state := snapshot.expressionProvenance(value.X)
		if isProjectionPayload(state) && scalarProjectionField(value.Sel.Name) {
			return projectionSelector
		}
		return state
	case *ast.StarExpr:
		return snapshot.expressionProvenance(value.X)
	case *ast.UnaryExpr:
		return snapshot.expressionProvenance(value.X)
	case *ast.SliceExpr:
		return snapshot.expressionProvenance(value.X)
	case *ast.IndexExpr:
		base := snapshot.expressionProvenance(value.X)
		if isProjectionPayload(base) {
			return projectionPayload
		}
		if base != projectionNone || snapshot.expressionProvenance(value.Index) != projectionNone {
			return projectionStructural
		}
	case *ast.IndexListExpr:
		base := snapshot.expressionProvenance(value.X)
		if isProjectionPayload(base) {
			return projectionPayload
		}
		for _, index := range value.Indices {
			if snapshot.expressionProvenance(index) != projectionNone {
				return projectionStructural
			}
		}
		return base
	case *ast.CompositeLit:
		state := projectionNone
		for _, element := range value.Elts {
			state = joinProjectionProvenance(state, snapshot.expressionProvenance(element))
		}
		return state
	case *ast.KeyValueExpr:
		return snapshot.expressionProvenance(value.Value)
	case *ast.FuncLit:
		state := projectionNone
		ast.Inspect(value.Body, func(node ast.Node) bool {
			if nested, ok := node.(*ast.FuncLit); ok && nested != value {
				return false
			}
			if nested, ok := node.(ast.Expr); ok {
				state = joinProjectionProvenance(state, snapshot.expressionProvenance(nested))
			}
			return true
		})
		return state
	case *ast.CallExpr:
		state := snapshot.expressionProvenance(value.Fun)
		for _, argument := range value.Args {
			state = joinProjectionProvenance(state, snapshot.expressionProvenance(argument))
		}
		if calledName(value.Fun) == "len" || calledName(value.Fun) == "cap" {
			if state != projectionNone {
				return projectionSelector
			}
		}
		return state
	}
	return projectionNone
}

func (snapshot lexicalSnapshot) expressionTainted(expression ast.Expr) bool {
	return isProjectionPayload(snapshot.expressionProvenance(expression))
}

// lexicalCallSnapshots walks statements in declaration order and records the
// environment visible at every call. It deliberately does not attempt runtime
// flow; each syntactically visible binding gets its Go lexical scope.
func lexicalCallSnapshots(function projectionFunction, carried map[string]projectionProvenance, localFunctions map[string][]projectionFunction) map[*ast.CallExpr]lexicalSnapshot {
	snapshots := make(map[*ast.CallExpr]lexicalSnapshot)
	root := newLexicalScope(function.closure)
	seedFields := func(fields *ast.FieldList) {
		if fields == nil {
			return
		}
		for _, field := range fields.List {
			receiver := normalizedReceiverType(field.Type, function.packagePath, function.imports)
			for _, name := range field.Names {
				if name.Name != "_" {
					// A ResolvedReport becomes projection data at its Findings field;
					// treating the whole report as a findings slice would taint every
					// unrelated report-aware helper result.
					root.bindings[name.Name] = lexicalBinding{present: true, receiver: receiver, provenance: carried[name.Name]}
				}
			}
		}
	}
	seedFields(function.signature.Params)
	seedFields(function.signature.Results)

	var walkExpr func(ast.Expr, *lexicalScope)
	var walkStmt func(ast.Stmt, *lexicalScope)
	var walkBlock func(*ast.BlockStmt, *lexicalScope)

	var receiverOf func(ast.Expr, *lexicalScope) string
	var expressionProvenance func(ast.Expr, *lexicalScope) projectionProvenance
	receiverOf = func(expression ast.Expr, scope *lexicalScope) string {
		expression = unwrapExpression(expression)
		if identifier, ok := expression.(*ast.Ident); ok {
			binding, _ := scope.lookup(identifier.Name)
			return binding.receiver
		}
		if unary, ok := expression.(*ast.UnaryExpr); ok && unary.Op == token.AND {
			return receiverOf(unary.X, scope)
		}
		if composite, ok := expression.(*ast.CompositeLit); ok {
			return normalizedReceiverType(composite.Type, function.packagePath, function.imports)
		}
		if call, ok := expression.(*ast.CallExpr); ok && calledName(call.Fun) == "new" && len(call.Args) == 1 {
			return normalizedReceiverType(call.Args[0], function.packagePath, function.imports)
		}
		if call, ok := expression.(*ast.CallExpr); ok {
			name := calledName(call.Fun)
			candidates := localFunctions[name]
			if len(candidates) == 1 && candidates[0].signature.Results != nil && len(candidates[0].signature.Results.List) == 1 {
				return normalizedReceiverType(candidates[0].signature.Results.List[0].Type, function.packagePath, function.imports)
			}
		}
		return ""
	}
	expressionProvenance = func(expression ast.Expr, scope *lexicalScope) projectionProvenance {
		for {
			parenthesized, ok := expression.(*ast.ParenExpr)
			if !ok {
				break
			}
			expression = parenthesized.X
		}
		switch value := expression.(type) {
		case *ast.Ident:
			binding, _ := scope.lookup(value.Name)
			return binding.provenance
		case *ast.SelectorExpr:
			if identifier, ok := unwrapExpression(value.X).(*ast.Ident); ok {
				binding, _ := scope.lookup(identifier.Name)
				if strings.HasSuffix(binding.receiver, "/oid:ResolvedReport") {
					if value.Sel.Name == "Findings" {
						return projectionPayload
					}
					return projectionSelector
				}
			}
			state := expressionProvenance(value.X, scope)
			if isProjectionPayload(state) && scalarProjectionField(value.Sel.Name) {
				return projectionSelector
			}
			return state
		case *ast.StarExpr:
			return expressionProvenance(value.X, scope)
		case *ast.UnaryExpr:
			return expressionProvenance(value.X, scope)
		case *ast.SliceExpr:
			return expressionProvenance(value.X, scope)
		case *ast.IndexExpr:
			base := expressionProvenance(value.X, scope)
			if isProjectionPayload(base) {
				return projectionPayload
			}
			if base != projectionNone || expressionProvenance(value.Index, scope) != projectionNone {
				return projectionStructural
			}
			return projectionNone
		case *ast.IndexListExpr:
			base := expressionProvenance(value.X, scope)
			if isProjectionPayload(base) {
				return projectionPayload
			}
			for _, index := range value.Indices {
				if expressionProvenance(index, scope) != projectionNone {
					return projectionStructural
				}
			}
			return base
		case *ast.CompositeLit:
			state := projectionNone
			for _, element := range value.Elts {
				state = joinProjectionProvenance(state, expressionProvenance(element, scope))
			}
			return state
		case *ast.KeyValueExpr:
			return expressionProvenance(value.Value, scope)
		case *ast.FuncLit:
			state := projectionNone
			ast.Inspect(value.Body, func(node ast.Node) bool {
				if nested, ok := node.(*ast.FuncLit); ok && nested != value {
					return false
				}
				if nestedExpression, ok := node.(ast.Expr); ok {
					state = joinProjectionProvenance(state, expressionProvenance(nestedExpression, scope))
				}
				return true
			})
			return state
		case *ast.CallExpr:
			// A locally declared concrete return type proves that the call result
			// is an object boundary rather than an untyped findings value. The
			// call edge still receives taint through projectionArguments.
			if receiverOf(value, scope) != "" {
				return projectionNone
			}
			state := expressionProvenance(value.Fun, scope)
			for _, argument := range value.Args {
				state = joinProjectionProvenance(state, expressionProvenance(argument, scope))
			}
			if calledName(value.Fun) == "len" || calledName(value.Fun) == "cap" {
				if state != projectionNone {
					return projectionSelector
				}
			}
			return state
		}
		return projectionNone
	}

	walkExpr = func(expression ast.Expr, scope *lexicalScope) {
		if expression == nil {
			return
		}
		ast.Inspect(expression, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.FuncLit:
				// The literal captures the current lexical facts, but it is not an
				// executed control-flow edge merely because it was declared.
				child := newLexicalScope(scope.clone())
				seedLiteralFields := func(fields *ast.FieldList) {
					if fields == nil {
						return
					}
					for _, field := range fields.List {
						receiver := normalizedReceiverType(field.Type, function.packagePath, function.imports)
						for _, name := range field.Names {
							if name.Name != "_" {
								child.bindings[name.Name] = lexicalBinding{present: true, receiver: receiver}
							}
						}
					}
				}
				seedLiteralFields(value.Type.Params)
				seedLiteralFields(value.Type.Results)
				walkBlock(value.Body, child)
				return false
			case *ast.CallExpr:
				snapshots[value] = scope.snapshot()
			}
			return true
		})
	}

	bindNames := func(names []*ast.Ident, values []ast.Expr, declaredType ast.Expr, scope *lexicalScope, define bool) {
		for index, name := range names {
			if name.Name == "_" {
				continue
			}
			receiver := ""
			if declaredType != nil {
				receiver = normalizedReceiverType(declaredType, function.packagePath, function.imports)
			} else if index < len(values) {
				receiver = receiverOf(values[index], scope)
			}
			binding := lexicalBinding{present: true, receiver: receiver}
			if index < len(values) {
				binding.alias = values[index]
				binding.provenance = expressionProvenance(values[index], scope)
			}
			if define {
				scope.bindings[name.Name] = binding
			} else if !scope.assign(name.Name, binding) {
				// Invalid Go source can be parsed for mutation tests; keep the
				// analyzer deterministic by treating an unbound '=' as local.
				scope.bindings[name.Name] = binding
			}
		}
	}
	shortDeclaration := func(assignment *ast.AssignStmt, scope *lexicalScope) {
		for index, expression := range assignment.Lhs {
			name, ok := expression.(*ast.Ident)
			if !ok {
				continue
			}
			var rhs []ast.Expr
			if index < len(assignment.Rhs) {
				rhs = assignment.Rhs[index : index+1]
			}
			_, exists := scope.bindings[name.Name]
			bindNames([]*ast.Ident{name}, rhs, nil, scope, !exists)
		}
	}
	assignmentNames := func(assignment *ast.AssignStmt) []*ast.Ident {
		names := make([]*ast.Ident, 0, len(assignment.Lhs))
		for _, expression := range assignment.Lhs {
			if name, ok := expression.(*ast.Ident); ok {
				names = append(names, name)
			}
		}
		return names
	}

	walkBlock = func(block *ast.BlockStmt, parent *lexicalScope) {
		if block == nil {
			return
		}
		scope := newLexicalScope(parent)
		for _, statement := range block.List {
			walkStmt(statement, scope)
		}
	}
	walkStmt = func(statement ast.Stmt, scope *lexicalScope) {
		switch value := statement.(type) {
		case *ast.BlockStmt:
			walkBlock(value, scope)
		case *ast.ExprStmt:
			walkExpr(value.X, scope)
		case *ast.DeclStmt:
			declaration, ok := value.Decl.(*ast.GenDecl)
			if !ok {
				return
			}
			for _, spec := range declaration.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, expression := range valueSpec.Values {
					walkExpr(expression, scope)
				}
				bindNames(valueSpec.Names, valueSpec.Values, valueSpec.Type, scope, true)
			}
		case *ast.AssignStmt:
			for _, expression := range value.Rhs {
				walkExpr(expression, scope)
			}
			for _, expression := range value.Lhs {
				if _, ok := expression.(*ast.Ident); !ok {
					walkExpr(expression, scope)
				}
			}
			if value.Tok == token.DEFINE {
				shortDeclaration(value, scope)
			} else {
				bindNames(assignmentNames(value), value.Rhs, nil, scope, false)
			}
		case *ast.ReturnStmt:
			for _, expression := range value.Results {
				walkExpr(expression, scope)
			}
		case *ast.GoStmt:
			walkExpr(value.Call, scope)
		case *ast.DeferStmt:
			walkExpr(value.Call, scope)
		case *ast.SendStmt:
			walkExpr(value.Chan, scope)
			walkExpr(value.Value, scope)
		case *ast.IncDecStmt:
			walkExpr(value.X, scope)
		case *ast.IfStmt:
			ifParent := scope.clone()
			ifScope := newLexicalScope(ifParent)
			if value.Init != nil {
				walkStmt(value.Init, ifScope)
			}
			walkExpr(value.Cond, ifScope)
			thenScope := ifScope.clone()
			walkBlock(value.Body, thenScope)
			elseScope := ifScope.clone()
			if value.Else != nil {
				walkStmt(value.Else, elseScope)
			}
			mergeControlOutcomes(scope, thenScope.parent, elseScope.parent)
		case *ast.ForStmt:
			forParent := scope.clone()
			forScope := newLexicalScope(forParent)
			if value.Init != nil {
				walkStmt(value.Init, forScope)
			}
			walkExpr(value.Cond, forScope)
			bodyScope := forScope.clone()
			walkBlock(value.Body, bodyScope)
			if value.Post != nil {
				walkStmt(value.Post, bodyScope)
			}
			mergeControlOutcomes(scope, forParent, bodyScope.parent)
		case *ast.RangeStmt:
			walkExpr(value.X, scope)
			baseScope := scope.clone()
			iterationScope := scope.clone()
			rangeScope := newLexicalScope(iterationScope)
			if value.Tok == token.DEFINE {
				if name, ok := value.Key.(*ast.Ident); ok && name.Name != "_" {
					rangeScope.bindings[name.Name] = lexicalBinding{present: true}
				}
				if name, ok := value.Value.(*ast.Ident); ok && name.Name != "_" {
					rangeScope.bindings[name.Name] = lexicalBinding{present: true}
				}
			}
			walkBlock(value.Body, rangeScope)
			mergeControlOutcomes(scope, baseScope, iterationScope)
		case *ast.SwitchStmt:
			switchParent := scope.clone()
			switchScope := newLexicalScope(switchParent)
			if value.Init != nil {
				walkStmt(value.Init, switchScope)
			}
			walkExpr(value.Tag, switchScope)
			outcomes := []*lexicalScope{switchParent.clone()}
			for _, clause := range value.Body.List {
				caseClause := clause.(*ast.CaseClause)
				caseScope := switchScope.clone()
				for _, expression := range caseClause.List {
					walkExpr(expression, caseScope)
				}
				for _, statement := range caseClause.Body {
					walkStmt(statement, caseScope)
				}
				outcomes = append(outcomes, caseScope.parent)
			}
			mergeControlOutcomes(scope, outcomes...)
		case *ast.TypeSwitchStmt:
			switchParent := scope.clone()
			switchScope := newLexicalScope(switchParent)
			if value.Init != nil {
				walkStmt(value.Init, switchScope)
			}
			walkStmt(value.Assign, switchScope)
			outcomes := []*lexicalScope{switchParent.clone()}
			for _, clause := range value.Body.List {
				caseClause := clause.(*ast.CaseClause)
				caseScope := switchScope.clone()
				for _, statement := range caseClause.Body {
					walkStmt(statement, caseScope)
				}
				outcomes = append(outcomes, caseScope.parent)
			}
			mergeControlOutcomes(scope, outcomes...)
		case *ast.SelectStmt:
			outcomes := []*lexicalScope{scope.clone()}
			for _, clause := range value.Body.List {
				communication := clause.(*ast.CommClause)
				caseParent := scope.clone()
				caseScope := newLexicalScope(caseParent)
				if communication.Comm != nil {
					walkStmt(communication.Comm, caseScope)
				}
				for _, statement := range communication.Body {
					walkStmt(statement, caseScope)
				}
				outcomes = append(outcomes, caseParent)
			}
			mergeControlOutcomes(scope, outcomes...)
		case *ast.LabeledStmt:
			walkStmt(value.Stmt, scope)
		}
	}
	if function.body != nil {
		for _, statement := range function.body.List {
			walkStmt(statement, root)
		}
	}
	return snapshots
}

func normalizedReceiverType(expression ast.Expr, packagePath string, imports map[string]string) string {
	expression = unwrapExpression(expression)
	if pointer, ok := expression.(*ast.StarExpr); ok {
		return normalizedReceiverType(pointer.X, packagePath, imports)
	}
	if identifier, ok := expression.(*ast.Ident); ok {
		return packagePath + ":" + identifier.Name
	}
	if selector, ok := expression.(*ast.SelectorExpr); ok {
		if identifier, ok := unwrapExpression(selector.X).(*ast.Ident); ok {
			for path, alias := range imports {
				if alias == identifier.Name {
					return path + ":" + selector.Sel.Name
				}
			}
		}
	}
	return ""
}

func methodReceiver(function *ast.FuncDecl, packagePath string, imports map[string]string) string {
	if function.Recv == nil || len(function.Recv.List) != 1 {
		return ""
	}
	return normalizedReceiverType(function.Recv.List[0].Type, packagePath, imports)
}

func methodKey(receiver, name string) string { return receiver + ":" + name }

func receiverPackage(receiver string) string {
	if index := strings.LastIndex(receiver, ":"); index >= 0 {
		return receiver[:index]
	}
	return ""
}

type callbackBinding struct {
	unknown bool
	targets map[string]projectionFunction
}

type callbackParameterSlot struct {
	name     string
	function bool
}

// flattenedCallbackParameters gives each declared function parameter one
// position. ast.Field groups declarations such as "first, cb func(...)" into
// one field, but calls are positional and therefore need two slots.
func flattenedCallbackParameters(fields *ast.FieldList) []callbackParameterSlot {
	if fields == nil {
		return nil
	}
	slots := make([]callbackParameterSlot, 0, len(fields.List))
	unnamed := 0
	for _, field := range fields.List {
		_, isFunction := unwrapExpression(field.Type).(*ast.FuncType)
		if len(field.Names) == 0 {
			slots = append(slots, callbackParameterSlot{name: fmt.Sprintf("__unnamed_callback_parameter_%d", unnamed), function: isFunction})
			unnamed++
			continue
		}
		for _, name := range field.Names {
			slots = append(slots, callbackParameterSlot{name: name.Name, function: isFunction})
		}
	}
	return slots
}

func flattenedParameterNames(fields *ast.FieldList) []string {
	if fields == nil {
		return nil
	}
	names := make([]string, 0, len(fields.List))
	unnamed := 0
	for _, field := range fields.List {
		if len(field.Names) == 0 {
			names = append(names, fmt.Sprintf("__unnamed_parameter_%d", unnamed))
			unnamed++
			continue
		}
		for _, name := range field.Names {
			names = append(names, name.Name)
		}
	}
	return names
}

func projectionArguments(call *ast.CallExpr, signature *ast.FuncType, snapshot lexicalSnapshot) map[string]projectionProvenance {
	if signature == nil {
		return nil
	}
	slots := flattenedParameterNames(signature.Params)
	var out map[string]projectionProvenance
	for index, argument := range call.Args {
		state := snapshot.expressionProvenance(argument)
		if index >= len(slots) || state == projectionNone {
			continue
		}
		if out == nil {
			out = make(map[string]projectionProvenance)
		}
		out[slots[index]] = joinProjectionProvenance(out[slots[index]], state)
	}
	return out
}

func canonicalProjectionState(state map[string]projectionProvenance) string {
	names := make([]string, 0, len(state))
	for name, provenance := range state {
		if provenance != projectionNone {
			names = append(names, name+fmt.Sprintf("=%d", provenance))
		}
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func projectionDataReceiver(expression ast.Expr, snapshot lexicalSnapshot) bool {
	expression = unwrapExpression(expression)
	switch value := expression.(type) {
	case *ast.Ident:
		binding := snapshot.bindings[value.Name]
		return isProjectionPayload(binding.provenance) && binding.receiver == ""
	case *ast.SelectorExpr:
		if !snapshot.expressionTainted(value) {
			return false
		}
		if identifier, ok := unwrapExpression(value.X).(*ast.Ident); ok && strings.HasSuffix(snapshot.bindings[identifier.Name].receiver, "/oid:ResolvedReport") {
			return value.Sel.Name == "Findings"
		}
		// A selector off a concrete non-report receiver is an object member, not
		// proof that the receiver itself is a findings value. Its exact method
		// type is resolved separately when available.
		return false
	case *ast.StarExpr, *ast.UnaryExpr, *ast.SliceExpr, *ast.IndexExpr, *ast.IndexListExpr, *ast.CompositeLit, *ast.CallExpr:
		return snapshot.expressionTainted(expression)
	}
	return false
}

func projectionCallTainted(call *ast.CallExpr, snapshot lexicalSnapshot, aliases map[string]ast.Expr, state map[string]callbackBinding) bool {
	if containsCallback(call.Fun, aliases, state) {
		return true
	}
	if selector, ok := unwrapExpression(call.Fun).(*ast.SelectorExpr); ok && projectionDataReceiver(selector.X, snapshot) {
		return true
	}
	for _, argument := range call.Args {
		if snapshot.expressionTainted(argument) || containsCallback(argument, aliases, state) {
			return true
		}
	}
	return false
}

func (binding callbackBinding) empty() bool {
	return !binding.unknown && len(binding.targets) == 0
}

func mergeCallbackBinding(left, right callbackBinding) callbackBinding {
	out := callbackBinding{unknown: left.unknown || right.unknown}
	if len(left.targets)+len(right.targets) > 0 {
		out.targets = make(map[string]projectionFunction, len(left.targets)+len(right.targets))
		for key, target := range left.targets {
			out.targets[key] = target
		}
		for key, target := range right.targets {
			out.targets[key] = target
		}
	}
	return out
}

func callbackTargetKey(target projectionFunction) string {
	return target.packagePath + ":" + target.name + ":" + target.file
}

func sourcePackage(path string) string {
	path = filepath.ToSlash(path)
	const module = "github.com/scanoss/crypto-finder"
	if index := strings.Index(path, "/internal/"); index >= 0 {
		return module + filepath.ToSlash(filepath.Dir(path[index:]))
	}
	if strings.HasPrefix(path, "../") {
		return module + "/internal/" + filepath.ToSlash(filepath.Dir(strings.TrimPrefix(path, "../")))
	}
	return filepath.ToSlash(filepath.Dir(path))
}

// checkResolvedProjectionInvariant follows statically identifiable call edges
// from ResolvedReport consumers across internal packages. Unknown dynamic calls
// are not claimed as proof; the production boundary has no such call edge.
func checkResolvedProjectionInvariant(sources map[string]string) ([]string, error) {
	functions := make(map[string]map[string][]projectionFunction)
	methods := make(map[string]map[string][]projectionFunction)
	packageAliases := make(map[string]map[string]ast.Expr)
	literalNumber := 0
	for path, source := range sources {
		file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			return nil, err
		}
		imports, pkg := localImportNames(file), sourcePackage(path)
		if functions[pkg] == nil {
			functions[pkg] = make(map[string][]projectionFunction)
		}
		if methods[pkg] == nil {
			methods[pkg] = make(map[string][]projectionFunction)
		}
		if packageAliases[pkg] == nil {
			packageAliases[pkg] = make(map[string]ast.Expr)
		}
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok {
				receiver := methodReceiver(function, pkg, imports)
				candidate := projectionFunction{name: function.Name.Name, file: path, packagePath: pkg, imports: imports, signature: function.Type, body: function.Body, receiver: receiver}
				if receiver == "" {
					functions[pkg][function.Name.Name] = append(functions[pkg][function.Name.Name], candidate)
				} else {
					methods[pkg][methodKey(receiver, function.Name.Name)] = append(methods[pkg][methodKey(receiver, function.Name.Name)], candidate)
				}
			}
			if declaration, ok := declaration.(*ast.GenDecl); ok {
				for _, spec := range declaration.Specs {
					if value, ok := spec.(*ast.ValueSpec); ok {
						for index, expression := range value.Values {
							if index < len(value.Names) {
								packageAliases[pkg][value.Names[index].Name] = expression
							}
						}
					}
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if literal, ok := node.(*ast.FuncLit); ok {
				resolved, has := imports["github.com/scanoss/crypto-finder/internal/oid"]
				if has && literal.Type.Params != nil && fieldListContains(literal.Type.Params, resolved, "ResolvedReport") {
					literalNumber++
					name := fmt.Sprintf("literal-%d", literalNumber)
					functions[pkg][name] = append(functions[pkg][name], projectionFunction{name: name, file: path, packagePath: pkg, imports: imports, signature: literal.Type, body: literal.Body})
				}
			}
			return true
		})
	}

	var violations []string
	visited := make(map[string]bool)
	var inspect func(projectionFunction, map[string]callbackBinding, map[string]projectionProvenance)
	inspect = func(function projectionFunction, carried map[string]callbackBinding, projection map[string]projectionProvenance) {
		if function.body == nil {
			return
		}
		state := callbackState(function.signature, function.body, carried, carried != nil || consumesResolvedReport(function))
		visitKey := fmt.Sprintf("%p:%s:%s", function.body, canonicalCallbackState(state), canonicalProjectionState(projection))
		if visited[visitKey] {
			return
		}
		visited[visitKey] = true

		interim, hasInterim := function.imports["github.com/scanoss/crypto-finder/internal/entities"]
		if hasInterim && function.signature.Results != nil && fieldListContains(function.signature.Results, interim, "InterimReport") {
			violations = append(violations, function.file+": raw-return")
		}
		snapshots := lexicalCallSnapshots(function, projection, functions[function.packagePath])
		aliases := functionAliases(function.body)
		for name, expression := range packageAliases[function.packagePath] {
			if _, exists := aliases[name]; !exists {
				aliases[name] = expression
			}
		}

		ast.Inspect(function.body, func(node ast.Node) bool {
			if literal, ok := node.(*ast.FuncLit); ok {
				if capturesCallback(literal.Body, aliases, state) {
					violations = append(violations, function.file+": unsupported-callback-transport")
				}
				return false
			}
			if hasInterim {
				switch n := node.(type) {
				case *ast.CompositeLit:
					if isNamedType(n.Type, interim, "InterimReport") {
						violations = append(violations, function.file+": raw-composite")
					}
				case *ast.ValueSpec:
					if n.Type != nil && isNamedType(n.Type, interim, "InterimReport") {
						violations = append(violations, function.file+": raw-declaration")
					}
				}
			}
			if composite, ok := node.(*ast.CompositeLit); ok && containsCallback(composite, aliases, state) {
				violations = append(violations, function.file+": unsupported-callback-transport")
			}
			if value, ok := node.(*ast.ValueSpec); ok && isInterfaceType(value.Type) && expressionsContainCallback(value.Values, aliases, state) {
				violations = append(violations, function.file+": unsupported-callback-transport")
			}
			if assignment, ok := node.(*ast.AssignStmt); ok && expressionsContainCallback(assignment.Rhs, aliases, state) && assignmentHasAggregateDestination(assignment.Lhs) {
				violations = append(violations, function.file+": unsupported-callback-transport")
			}
			if returned, ok := node.(*ast.ReturnStmt); ok && expressionsContainCallback(returned.Results, aliases, state) {
				violations = append(violations, function.file+": unsupported-callback-transport")
			}

			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if hasInterim && isNamedType(call.Fun, interim, "InterimReport") {
				violations = append(violations, function.file+": raw-conversion")
			}
			if hasInterim && calledName(call.Fun) == "new" && len(call.Args) == 1 && isNamedType(call.Args[0], interim, "InterimReport") {
				violations = append(violations, function.file+": raw-allocation")
			}
			if calledName(call.Fun) == "AssignOccurrenceKeys" {
				violations = append(violations, function.file+": occurrence-mutation")
			}
			snapshot := snapshots[call]
			callAliases := snapshot.aliases()
			for name, expression := range packageAliases[function.packagePath] {
				if !snapshot.present(name) {
					callAliases[name] = expression
				}
			}
			callee := resolveAlias(unwrapExpression(call.Fun), callAliases)
			if literal, ok := callee.(*ast.FuncLit); ok {
				closure := newLexicalScope(nil)
				for name, binding := range snapshot.bindings {
					closure.bindings[name] = binding
				}
				inspect(projectionFunction{name: "literal", file: function.file, packagePath: function.packagePath, imports: function.imports, signature: literal.Type, body: literal.Body, closure: closure}, state, projectionArguments(call, literal.Type, snapshot))
				return true
			}
			name := calledName(callee)
			targetPackage := function.packagePath
			methodCall := false
			//nolint:nestif // receiver/package resolution must preserve fail-closed branches.
			if selector, ok := callee.(*ast.SelectorExpr); ok {
				if id, ok := unwrapExpression(selector.X).(*ast.Ident); ok {
					isImport := false
					receiver, local := snapshot.receiver(id.Name)
					if !local {
						for path, alias := range function.imports {
							if alias == id.Name {
								targetPackage = path
								isImport = true
								break
							}
						}
					}
					if !isImport {
						methodCall = true
						if receiver != "" {
							targets := methods[receiverPackage(receiver)][methodKey(receiver, selector.Sel.Name)]
							if len(targets) > 0 {
								for _, target := range targets {
									next, unsupported := callbackArguments(call, target.signature, function, callAliases, state, functions, callCarriesResolvedProjection(call, function))
									if unsupported || (functionReturnsCallback(target.signature) && !callbackStateEmpty(next)) {
										violations = append(violations, function.file+": unsupported-callback-transport")
									}
									inspect(target, next, projectionArguments(call, target.signature, snapshot))
								}
								return true
							}
						}
					}
				}
			}
			if _, ok := callee.(*ast.SelectorExpr); ok && targetPackage == function.packagePath && !methodCall && callCarriesResolvedProjection(call, function) {
				methodCall = true
			}
			if _, ok := callee.(*ast.SelectorExpr); ok && targetPackage == function.packagePath && !methodCall {
				// A selector whose left side is not an import is method-shaped,
				// including selector and call-chain receivers.
				methodCall = true
			}
			if methodCall {
				// A selector that did not return through exact receiver-aware
				// dispatch is never a free-function call, even when its receiver
				// type is known but has no indexed method.
				if projectionCallTainted(call, snapshot, callAliases, state) {
					violations = append(violations, function.file+": unresolved-method-call")
				}
				return true
			}
			targets := functions[targetPackage][name]
			for _, target := range targets {
				if targetPackage != function.packagePath {
					// Function-valued provenance is deliberately a same-module
					// analysis. Crossing a package would require type information
					// that this structural checker does not own.
					inspect(target, nil, projectionArguments(call, target.signature, snapshot))
					continue
				}
				next, unsupported := callbackArguments(call, target.signature, function, callAliases, state, functions, callCarriesResolvedProjection(call, function))
				if unsupported || (functionReturnsCallback(target.signature) && !callbackStateEmpty(next)) {
					violations = append(violations, function.file+": unsupported-callback-transport")
				}
				inspect(target, next, projectionArguments(call, target.signature, snapshot))
			}
			if len(targets) == 0 {
				binding, known := resolveCallbackBinding(call.Fun, function, callAliases, state, functions)
				if known {
					for _, target := range binding.targets {
						inspect(target, nil, projectionArguments(call, target.signature, snapshot))
					}
					if binding.unknown || len(binding.targets) == 0 {
						violations = append(violations, function.file+": unresolved-dynamic-call")
					}
				}
			}
			return true
		})
	}
	for _, packageFunctions := range functions {
		for _, candidates := range packageFunctions {
			for _, function := range candidates {
				resolved, ok := function.imports["github.com/scanoss/crypto-finder/internal/oid"]
				if ok && function.signature.Params != nil && fieldListContains(function.signature.Params, resolved, "ResolvedReport") {
					inspect(function, nil, nil)
				}
			}
		}
	}
	return violations, nil
}

func callbackState(signature *ast.FuncType, body *ast.BlockStmt, carried map[string]callbackBinding, seedUnknown bool) map[string]callbackBinding {
	out := make(map[string]callbackBinding)
	addUnknown := func(fields *ast.FieldList) {
		for _, slot := range flattenedCallbackParameters(fields) {
			if slot.function {
				out[slot.name] = callbackBinding{unknown: true}
			}
		}
	}
	if seedUnknown {
		addUnknown(signature.Params)
		ast.Inspect(body, func(node ast.Node) bool {
			if _, ok := node.(*ast.FuncLit); ok {
				return false
			}
			if value, ok := node.(*ast.ValueSpec); ok {
				addUnknown(&ast.FieldList{List: []*ast.Field{{Names: value.Names, Type: value.Type}}})
			}
			return true
		})
	}
	for name, binding := range carried {
		// A propagated argument is the concrete state of the callee parameter;
		// it refines the declaration's conservative unknown seed.
		out[name] = binding
	}
	return out
}

func consumesResolvedReport(function projectionFunction) bool {
	resolved, ok := function.imports["github.com/scanoss/crypto-finder/internal/oid"]
	return ok && function.signature.Params != nil && fieldListContains(function.signature.Params, resolved, "ResolvedReport")
}

func canonicalCallbackState(state map[string]callbackBinding) string {
	names := make([]string, 0, len(state))
	for name := range state {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		binding := state[name]
		targets := make([]string, 0, len(binding.targets))
		for key := range binding.targets {
			targets = append(targets, key)
		}
		sort.Strings(targets)
		prefix := ""
		if binding.unknown {
			prefix = "?"
		}
		parts = append(parts, name+"="+prefix+strings.Join(targets, "+"))
	}
	return strings.Join(parts, ",")
}

func callbackStateEmpty(state map[string]callbackBinding) bool {
	for _, binding := range state {
		if !binding.empty() {
			return false
		}
	}
	return true
}

func functionReturnsCallback(signature *ast.FuncType) bool {
	if signature.Results == nil {
		return false
	}
	for _, field := range signature.Results.List {
		if _, ok := unwrapExpression(field.Type).(*ast.FuncType); ok {
			return true
		}
	}
	return false
}

func resolveCallbackBinding(expression ast.Expr, function projectionFunction, aliases map[string]ast.Expr, state map[string]callbackBinding, functions map[string]map[string][]projectionFunction) (callbackBinding, bool) {
	seen := map[string]bool{}
	for {
		expression = unwrapExpression(expression)
		identifier, ok := expression.(*ast.Ident)
		if !ok {
			return callbackBinding{unknown: true}, false
		}
		if binding, ok := state[identifier.Name]; ok {
			return binding, true
		}
		if seen[identifier.Name] {
			return callbackBinding{unknown: true}, true
		}
		seen[identifier.Name] = true
		if alias, ok := aliases[identifier.Name]; ok {
			expression = alias
			continue
		}
		targets := functions[function.packagePath][identifier.Name]
		if len(targets) == 0 {
			return callbackBinding{unknown: true}, false
		}
		binding := callbackBinding{targets: make(map[string]projectionFunction, len(targets))}
		for _, target := range targets {
			binding.targets[callbackTargetKey(target)] = target
		}
		return binding, true
	}
}

func callbackArguments(call *ast.CallExpr, signature *ast.FuncType, function projectionFunction, aliases map[string]ast.Expr, state map[string]callbackBinding, functions map[string]map[string][]projectionFunction, carriesResolvedProjection bool) (map[string]callbackBinding, bool) {
	var out map[string]callbackBinding
	unsupported := false
	if signature.Params == nil {
		return out, unsupported
	}
	slots := flattenedCallbackParameters(signature.Params)
	for i, arg := range call.Args {
		if i >= len(slots) {
			break
		}
		slot := slots[i]
		if !slot.function {
			continue
		}
		binding, known := resolveCallbackBinding(arg, function, aliases, state, functions)
		if !known {
			unsupported = unsupported || carriesResolvedProjection
			continue
		}
		if out == nil {
			out = make(map[string]callbackBinding)
		}
		out[slot.name] = mergeCallbackBinding(out[slot.name], binding)
	}
	return out, unsupported
}

func callCarriesResolvedProjection(call *ast.CallExpr, function projectionFunction) bool {
	resolved, ok := function.imports["github.com/scanoss/crypto-finder/internal/oid"]
	if !ok || function.signature.Params == nil {
		return false
	}
	names := map[string]bool{}
	for _, field := range function.signature.Params.List {
		if !isNamedType(field.Type, resolved, "ResolvedReport") {
			continue
		}
		for _, name := range field.Names {
			names[name.Name] = true
		}
	}
	for _, argument := range call.Args {
		selector, ok := unwrapExpression(argument).(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Findings" {
			continue
		}
		if identifier, ok := unwrapExpression(selector.X).(*ast.Ident); ok && names[identifier.Name] {
			return true
		}
	}
	return false
}

func containsCallback(node ast.Node, aliases map[string]ast.Expr, state map[string]callbackBinding) bool {
	found := false
	ast.Inspect(node, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if !ok {
			return true
		}
		binding, known := callbackStateBinding(identifier, aliases, state)
		if known && !binding.empty() {
			found = true
			return false
		}
		return true
	})
	return found
}

func callbackStateBinding(expression ast.Expr, aliases map[string]ast.Expr, state map[string]callbackBinding) (callbackBinding, bool) {
	seen := map[string]bool{}
	for {
		identifier, ok := unwrapExpression(expression).(*ast.Ident)
		if !ok {
			return callbackBinding{}, false
		}
		if binding, ok := state[identifier.Name]; ok {
			return binding, true
		}
		if seen[identifier.Name] {
			return callbackBinding{unknown: true}, true
		}
		seen[identifier.Name] = true
		alias, ok := aliases[identifier.Name]
		if !ok {
			return callbackBinding{}, false
		}
		expression = alias
	}
}

func expressionsContainCallback(expressions []ast.Expr, aliases map[string]ast.Expr, state map[string]callbackBinding) bool {
	for _, expression := range expressions {
		if containsCallback(expression, aliases, state) {
			return true
		}
	}
	return false
}

func capturesCallback(body *ast.BlockStmt, aliases map[string]ast.Expr, state map[string]callbackBinding) bool {
	return containsCallback(body, aliases, state)
}

func isInterfaceType(expression ast.Expr) bool {
	_, ok := unwrapExpression(expression).(*ast.InterfaceType)
	return ok
}

func assignmentHasAggregateDestination(expressions []ast.Expr) bool {
	for _, expression := range expressions {
		if _, ok := unwrapExpression(expression).(*ast.SelectorExpr); ok {
			return true
		}
		if _, ok := unwrapExpression(expression).(*ast.IndexExpr); ok {
			return true
		}
	}
	return false
}

func functionAliases(body *ast.BlockStmt) map[string]ast.Expr {
	aliases := map[string]ast.Expr{}
	ast.Inspect(body, func(node ast.Node) bool {
		if _, ok := node.(*ast.FuncLit); ok {
			return false
		}
		switch n := node.(type) {
		case *ast.AssignStmt:
			for i, r := range n.Rhs {
				if i < len(n.Lhs) {
					if id, ok := n.Lhs[i].(*ast.Ident); ok {
						aliases[id.Name] = r
					}
				}
			}
		case *ast.ValueSpec:
			for i, r := range n.Values {
				if i < len(n.Names) {
					aliases[n.Names[i].Name] = r
				}
			}
		}
		return true
	})
	return aliases
}

func TestResolvedProjectionInvariantIndependentMutationMatrix(t *testing.T) {
	base := "github.com/scanoss/crypto-finder/internal/scan/synthetic.go"
	cases := []struct {
		name, source, category string
		extra                  map[string]string
	}{
		{"parenthesized conversion", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport){ _ = (*entities.InterimReport)(r) }`, "raw-conversion", nil},
		{"generic helper", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport){ generic[[]entities.Finding](r.Findings) }
func generic[T any](v T){ _ = &entities.InterimReport{}; _ = v }`, "raw-composite", nil},
		{"function alias", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport){ next := rawHelper; next(r.Findings) }
func rawHelper(v []entities.Finding){ _ = &entities.InterimReport{Findings:v} }`, "raw-composite", nil},
		{"cross package helper", `package scan
import (h "github.com/scanoss/crypto-finder/internal/helper"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport){ h.Project(r.Findings) }`, "raw-composite", map[string]string{"github.com/scanoss/crypto-finder/internal/helper/helper.go": `package helper
import "github.com/scanoss/crypto-finder/internal/entities"
func Project(v []entities.Finding){ _ = &entities.InterimReport{Findings:v} }`}},
		{"composite literal", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport){ _ = r.Findings; _ = &entities.InterimReport{} }`, "raw-composite", nil},
		{"field reconstruction", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport){ var raw entities.InterimReport; raw.Findings=r.Findings }`, "raw-declaration", nil},
		{"raw return exposure", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport){ _=r.Findings; _=expose() }
func expose() *entities.InterimReport { return nil }`, "raw-return", nil},
		{"direct mutation", `package scan
import ("github.com/scanoss/crypto-finder/internal/engine"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport, d *engine.DepScanResult){ _=r.Findings; AssignOccurrenceKeys(d) }`, "occurrence-mutation", nil},
		{"wrapped mutation", `package scan
import ("github.com/scanoss/crypto-finder/internal/engine"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport, d *engine.DepScanResult){ _=r.Findings; wrap(d) }
func wrap(d *engine.DepScanResult){ AssignOccurrenceKeys(d) }`, "occurrence-mutation", nil},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			sources := map[string]string{base: tt.source}
			for path, source := range tt.extra {
				sources[path] = source
			}
			violations, err := checkResolvedProjectionInvariant(sources)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(violations, "\n"), tt.category) {
				t.Fatalf("violations = %v, want category %q", violations, tt.category)
			}
		})
	}
}

func resolveAlias(expression ast.Expr, aliases map[string]ast.Expr) ast.Expr {
	seen := map[string]bool{}
	for {
		id, ok := unwrapExpression(expression).(*ast.Ident)
		if !ok || seen[id.Name] {
			return unwrapExpression(expression)
		}
		seen[id.Name] = true
		next, ok := aliases[id.Name]
		if !ok {
			return unwrapExpression(expression)
		}
		expression = next
	}
}

func TestResolvedProjectionInvariantOverlayBypasses(t *testing.T) {
	cases := []struct{ name, source, category string }{
		{"uninvoked resolved literal", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func f(){ _=func(r *oid.ResolvedReport){ _=&entities.InterimReport{} } }`, "raw-composite"},
		{"two hop alias", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport){ one:=two; two:=raw; one(r.Findings) }
func raw(v []entities.Finding){ _=&entities.InterimReport{}; _=v }`, "raw-composite"},
		{"package alias", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
var project = raw
func entry(r *oid.ResolvedReport){ project(r.Findings) }
func raw(v []entities.Finding){ _=&entities.InterimReport{}; _=v }`, "raw-composite"},
		{"alias cycle deterministic", `package scan
import "github.com/scanoss/crypto-finder/internal/oid"
func entry(r *oid.ResolvedReport){ a:=b; b:=a; a(r.Findings) }`, "unresolved-dynamic-call"},
		{"dynamic callback", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport, callback func([]entities.Finding)){ callback(r.Findings) }`, "unresolved-dynamic-call"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			v, e := checkResolvedProjectionInvariant(map[string]string{"synthetic.go": tt.source})
			if e != nil {
				t.Fatal(e)
			}
			if !strings.Contains(strings.Join(v, "\n"), tt.category) {
				t.Fatalf("%v want %s", v, tt.category)
			}
		})
	}
}

func TestResolvedProjectionInvariantHelperCallbackRelay(t *testing.T) {
	source := `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport, cb func([]entities.Finding)){ relay(cb,r.Findings) }
func relay(cb func([]entities.Finding), v []entities.Finding){ cb(v) }
func relayAgain(cb func([]entities.Finding), v []entities.Finding){ relay(cb,v) }
func twoHop(r *oid.ResolvedReport, cb func([]entities.Finding)){ relayAgain(cb, r.Findings) }
func safe(r *oid.ResolvedReport){ project(r.Findings) }
func project(v []entities.Finding){ _=len(v) }`
	v, e := checkResolvedProjectionInvariant(map[string]string{"synthetic.go": source})
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(strings.Join(v, "\n"), "unresolved-dynamic-call") {
		t.Fatalf("%v", v)
	}
}

func TestResolvedProjectionInvariantCallbackStateMatrix(t *testing.T) {
	cases := []struct {
		name, source, wantDiagnostic string
	}{
		{"callback alias", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport, cb func([]entities.Finding)){ alias:=cb; relay(alias,r.Findings) }
func relay(cb func([]entities.Finding), v []entities.Finding){ cb(v) }`, "unresolved-dynamic-call"},
		{"unsafe static target", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport){ relay(unsafe,r.Findings) }
func relay(cb func([]entities.Finding), v []entities.Finding){ cb(v) }
func unsafe(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }`, "raw-composite"},
		{"safe static target", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport){ relay(safe,r.Findings) }
func relay(cb func([]entities.Finding), v []entities.Finding){ cb(v) }
func safe(v []entities.Finding){ _=len(v) }`, ""},
		{"aggregate transport", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type box struct{ fn func([]entities.Finding) }
func entry(r *oid.ResolvedReport, cb func([]entities.Finding)){ b:=box{fn:cb}; b.fn(r.Findings) }`, "unsupported-callback-transport"},
		{"identity return transport", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport, cb func([]entities.Finding)){ next:=identity(cb); next(r.Findings) }
func identity(cb func([]entities.Finding)) func([]entities.Finding) { return cb }`, "unsupported-callback-transport"},
		{"safe first then dynamic", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport, cb func([]entities.Finding)){ relay(safe,r.Findings); relay(cb,r.Findings) }
func relay(cb func([]entities.Finding), v []entities.Finding){ cb(v) }
func safe(v []entities.Finding){ _=len(v) }`, "unresolved-dynamic-call"},
		{"actual two hop relay", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport){ relayAgain(unsafe,r.Findings) }
func relayAgain(cb func([]entities.Finding), v []entities.Finding){ relay(cb,v) }
func relay(cb func([]entities.Finding), v []entities.Finding){ cb(v) }
func unsafe(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }`, "raw-composite"},
		{"deeper relay", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport){ one(unsafe,r.Findings) }
func one(cb func([]entities.Finding), v []entities.Finding){ two(cb,v) }
func two(cb func([]entities.Finding), v []entities.Finding){ three(cb,v) }
func three(cb func([]entities.Finding), v []entities.Finding){ cb(v) }
func unsafe(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }`, "raw-composite"},
		{"target and alias cycles", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport, cb func([]entities.Finding)){ a:=b; b:=a; relay(cb,r.Findings); a(r.Findings) }
func relay(cb func([]entities.Finding), v []entities.Finding){ relay(cb,v) }`, "unresolved-dynamic-call"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := checkResolvedProjectionInvariant(map[string]string{"synthetic.go": tt.source})
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(violations, "\n")
			if tt.wantDiagnostic == "" {
				if got != "" {
					t.Fatalf("violations = %q, want none", got)
				}
				return
			}
			if !strings.Contains(got, tt.wantDiagnostic) {
				t.Fatalf("violations = %q, want %q", got, tt.wantDiagnostic)
			}
		})
	}
}

func TestResolvedProjectionInvariantGroupedCallbacksAndMethodValues(t *testing.T) {
	cases := []struct{ name, source, wantDiagnostic string }{
		{"grouped callback first slot", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport, cb func([]entities.Finding)){ relay(cb, safe, r.Findings) }
func relay(first, cb func([]entities.Finding), v []entities.Finding){ first(v) }
func safe(v []entities.Finding){ _=len(v) }`, "unresolved-dynamic-call"},
		{"grouped callback middle slot", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport, cb func([]entities.Finding)){ relay(0, safe, cb, r.Findings) }
func relay(n int, first, cb func([]entities.Finding), v []entities.Finding){ _=n; cb(v) }
func safe(v []entities.Finding){ _=len(v) }`, "unresolved-dynamic-call"},
		{"grouped callback final slot", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport, cb func([]entities.Finding)){ relay(0, safe, cb, r.Findings) }
func relay(n int, first, cb func([]entities.Finding), v []entities.Finding){ _=n; cb(v) }
func safe(v []entities.Finding){ _=len(v) }`, "unresolved-dynamic-call"},
		{"mixed grouped and ungrouped callback fields", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport, cb func([]entities.Finding)){ relay(safe, cb, 1, r.Findings) }
func relay(first, cb func([]entities.Finding), marker int, v []entities.Finding){ _=first; _=marker; cb(v) }
func safe(v []entities.Finding){ _=len(v) }`, "unresolved-dynamic-call"},
		{"unnamed callback slot preserves following position", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport, cb func([]entities.Finding)){ relay(safe, cb, r.Findings) }
func relay(_ func([]entities.Finding), cb func([]entities.Finding), v []entities.Finding){ cb(v) }
func safe(v []entities.Finding){ _=len(v) }`, "unresolved-dynamic-call"},
		{"unsafe method value fails closed despite safe namesake", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safeReceiver struct{}; type unsafeReceiver struct{}
func (safeReceiver) project(v []entities.Finding){ _=len(v) }
func (unsafeReceiver) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport){ var u unsafeReceiver; relay(u.project,r.Findings) }
func relay(cb func([]entities.Finding), v []entities.Finding){ cb(v) }`, "unsupported-callback-transport"},
		{"safe method value does not resolve by bare method name", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safeReceiver struct{}; type unsafeReceiver struct{}
func (safeReceiver) project(v []entities.Finding){ _=len(v) }
func (unsafeReceiver) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport){ var s safeReceiver; relay(s.project,r.Findings) }
func relay(cb func([]entities.Finding), v []entities.Finding){ cb(v) }`, "unsupported-callback-transport"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := checkResolvedProjectionInvariant(map[string]string{"synthetic.go": tt.source})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(violations, "\n"); !strings.Contains(got, tt.wantDiagnostic) {
				t.Fatalf("violations = %q, want %q", got, tt.wantDiagnostic)
			}
		})
	}
}

func TestResolvedProjectionInvariantReceiverAwareMethods(t *testing.T) {
	cases := []struct {
		name, source, want string
		extra              map[string]string
	}{
		{"safe and unsafe namesakes dispatch by receiver", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}; type unsafe struct{}
func (safe) project(v []entities.Finding){ _=len(v) }
func (*unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport){ var s safe; s.project(r.Findings) }`, "", nil},
		{"unsafe direct method diagnoses raw construction", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}; type unsafe struct{}
func (safe) project(v []entities.Finding){ _=len(v) }
func (*unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport){ var u unsafe; u.project(r.Findings) }`, "raw-composite", nil},
		{"pointer value and alias normalize receiver", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}
func (*safe) project(v []entities.Finding){ _=len(v) }
func entry(r *oid.ResolvedReport){ p:=&safe{}; alias:=p; alias.project(r.Findings) }`, "", nil},
		{"imported receiver method resolves when source is available", `package scan
import (h "github.com/scanoss/crypto-finder/internal/helper"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport){ var s h.Safe; s.Project(r.Findings) }`, "", map[string]string{"github.com/scanoss/crypto-finder/internal/helper/helper.go": `package helper
import "github.com/scanoss/crypto-finder/internal/entities"
type Safe struct{}
func (Safe) Project(v []entities.Finding){ _=len(v) }`}},
		{"unknown receiver fails closed", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport, unknown any){ unknown.project(r.Findings) }`, "unresolved-method-call", nil},
		{"method value remains unsupported", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}
func (safe) project(v []entities.Finding){ _=len(v) }
func entry(r *oid.ResolvedReport){ var s safe; relay(s.project,r.Findings) }
func relay(cb func([]entities.Finding), v []entities.Finding){ cb(v) }`, "unsupported-callback-transport", nil},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			sources := map[string]string{"synthetic.go": tt.source}
			for path, source := range tt.extra {
				sources[path] = source
			}
			got, err := checkResolvedProjectionInvariant(sources)
			if err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(got, "\n")
			if tt.want == "" && joined != "" {
				t.Fatalf("violations = %q, want none", joined)
			}
			if tt.want != "" && !strings.Contains(joined, tt.want) {
				t.Fatalf("violations = %q, want %q", joined, tt.want)
			}
		})
	}
}

func TestResolvedProjectionInvariantSelectorBypasses(t *testing.T) {
	cases := []struct{ name, source, want string }{
		{"method expression fails closed", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type unsafe struct{}; func (unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport){ unsafe.project(unsafe{},r.Findings) }`, "unresolved-method-call"},
		{"selector chain fails closed", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type unsafe struct{}; type holder struct{ u unsafe }; func (unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport){ var h holder; h.u.project(r.Findings) }`, "unresolved-method-call"},
		{"call chain receiver fails closed", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type unsafe struct{}; func (unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }; func makeUnsafe() unsafe { return unsafe{} }
func entry(r *oid.ResolvedReport){ makeUnsafe().project(r.Findings) }`, "unresolved-method-call"},
		{"safe direct and package function remain allowed", `package scan
import (h "github.com/scanoss/crypto-finder/internal/helper"; "github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}; func (safe) project(v []entities.Finding){ _=len(v) }; func project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport){ var s safe; s.project(r.Findings); h.Project(r.Findings) }`, ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := checkResolvedProjectionInvariant(map[string]string{"synthetic.go": tt.source})
			if err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(got, "\n")
			if tt.want == "" && joined != "" {
				t.Fatalf("%q", joined)
			}
			if tt.want != "" && !strings.Contains(joined, tt.want) {
				t.Fatalf("%q want %q", joined, tt.want)
			}
		})
	}
}

func TestResolvedProjectionInvariantMethodShapedSafety(t *testing.T) {
	cases := []struct{ name, source, want string }{
		{"promoted method never falls back", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type unsafe struct{}; func (unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }; type outer struct{ unsafe }; func project(v []entities.Finding){ _=len(v) }
func entry(r *oid.ResolvedReport){ var o outer; o.project(r.Findings) }`, "unresolved-method-call"},
		{"interface dispatch fails closed", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type callback interface{ project([]entities.Finding) }; func project(v []entities.Finding){ _=len(v) }
func entry(r *oid.ResolvedReport, c callback){ c.project(r.Findings) }`, "unresolved-method-call"},
		{"receiver shadows import alias", `package scan
import (h "github.com/scanoss/crypto-finder/internal/helper"; "github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type unsafe struct{}; func (unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport){ var h unsafe; h.project(r.Findings) }`, "raw-composite"},
		{"safe method and package function controls", `package scan
import (h "github.com/scanoss/crypto-finder/internal/helper"; "github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}; func (safe) project(v []entities.Finding){ _=len(v) }
func entry(r *oid.ResolvedReport){ var s safe; s.project(r.Findings); h.Project(r.Findings) }`, ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			v, e := checkResolvedProjectionInvariant(map[string]string{"synthetic.go": tt.source})
			if e != nil {
				t.Fatal(e)
			}
			g := strings.Join(v, "\n")
			if tt.want == "" && g != "" {
				t.Fatal(g)
			}
			if tt.want != "" && !strings.Contains(g, tt.want) {
				t.Fatalf("%s want %s", g, tt.want)
			}
		})
	}
}

func TestResolvedProjectionInvariantLexicalSelectorScope(t *testing.T) {
	cases := []struct{ name, source, want string }{
		{"local shadow wins only after its declaration", `package scan
import (h "github.com/scanoss/crypto-finder/internal/helper"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport){ h.Project(r.Findings); var h any; h.Project(r.Findings) }`, "unresolved-method-call"},
		{"inner safe shadow does not replace outer unsafe receiver", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}; type unsafe struct{}
func (safe) project(v []entities.Finding){ _=len(v) }; func (unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport){ var u unsafe; u.project(r.Findings); { var u safe; u.project(r.Findings) }; u.project(r.Findings) }`, "raw-composite"},
		{"branch shadows do not leak", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}; type unsafe struct{}
func (safe) project(v []entities.Finding){ _=len(v) }; func (unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport, yes bool){ var u unsafe; if yes { var u safe; u.project(r.Findings) } else { u.project(r.Findings) }; u.project(r.Findings) }`, "raw-composite"},
		{"for init shadow does not leak", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}; type unsafe struct{}
func (safe) project(v []entities.Finding){ _=len(v) }; func (unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport, keep bool){ var u unsafe; for u := (safe{}); keep; { u.project(r.Findings); break }; u.project(r.Findings) }`, "raw-composite"},
		{"loop range and switch shadows do not leak", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}; type unsafe struct{}
func (safe) project(v []entities.Finding){ _=len(v) }; func (unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport, values []int, n int){ var u unsafe; for _, n := range values { _=n; var u safe; u.project(r.Findings) }; switch n { case 1: var u safe; u.project(r.Findings); default: u.project(r.Findings) }; u.project(r.Findings) }`, "raw-composite"},
		{"short declaration rhs sees outer receiver", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type unsafe struct{}; func (unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport){ var u unsafe; { u, marker := u, 1; _=marker; u.project(r.Findings) } }`, "raw-composite"},
		{"literal closure preserves outer while parameter shadows", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}; type unsafe struct{}
func (safe) project(v []entities.Finding){ _=len(v) }; func (unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport){ var u unsafe; func(){ u.project(r.Findings) }(); func(u safe){ u.project(r.Findings) }(safe{}) }`, "raw-composite"},
		{"unshadowed package function remains valid", `package scan
import (h "github.com/scanoss/crypto-finder/internal/helper"; "github.com/scanoss/crypto-finder/internal/oid")
func entry(r *oid.ResolvedReport){ h.Project(r.Findings) }`, ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := checkResolvedProjectionInvariant(map[string]string{"synthetic.go": tt.source})
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(violations, "\n")
			if tt.want == "" && got != "" {
				t.Fatalf("violations = %q, want none", got)
			}
			if tt.want != "" && !strings.Contains(got, tt.want) {
				t.Fatalf("violations = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolvedProjectionInvariantLexicalControlFlowIsolation(t *testing.T) {
	cases := []struct{ name, source, want string }{
		{"branch assignment does not replace outer receiver", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}; type unsafe struct{}
func (safe) project(v []entities.Finding){ _=len(v) }; func (unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport, yes bool){ var u unsafe; if yes { u=safe{} }; u.project(r.Findings) }`, "unresolved-method-call"},
		{"if else outcomes remain isolated", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}; type unsafe struct{}
func (safe) project(v []entities.Finding){ _=len(v) }; func (unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport, yes bool){ var u unsafe; if yes { u=safe{} } else { u=unsafe{} }; u.project(r.Findings) }`, "unresolved-method-call"},
		{"switch outcomes remain isolated", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}; type unsafe struct{}
func (safe) project(v []entities.Finding){ _=len(v) }; func (unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport, n int){ var u unsafe; switch n { case 1: u=safe{}; default: u=unsafe{} }; u.project(r.Findings) }`, "unresolved-method-call"},
		{"select outcomes remain isolated", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}; type unsafe struct{}
func (safe) project(v []entities.Finding){ _=len(v) }; func (unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport, ch <-chan struct{}){ var u unsafe; select { case <-ch: u=safe{}; default: u=unsafe{} }; u.project(r.Findings) }`, "unresolved-method-call"},
		{"uninvoked literal cannot mutate captured receiver", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}; type unsafe struct{}
func (safe) project(v []entities.Finding){ _=len(v) }; func (unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport){ var u unsafe; _=func(){ u=safe{} }; u.project(r.Findings) }`, "raw-composite"},
		{"zero iteration loop preserves ambiguity", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}; type unsafe struct{}
func (safe) project(v []entities.Finding){ _=len(v) }; func (unsafe) project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport, values []int){ var u unsafe; for range values { u=safe{} }; u.project(r.Findings) }`, "unresolved-method-call"},
		{"exact safe method and package function controls", `package scan
import (h "github.com/scanoss/crypto-finder/internal/helper"; "github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type safe struct{}; func (safe) project(v []entities.Finding){ _=len(v) }
func entry(r *oid.ResolvedReport){ var s safe; s.project(r.Findings); h.Project(r.Findings) }`, ""},
		{"method shaped selector never reaches namesake free function", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type receiver struct{}
func project(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }
func entry(r *oid.ResolvedReport){ var v receiver; v.project(r.Findings) }`, "unresolved-method-call"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := checkResolvedProjectionInvariant(map[string]string{"synthetic.go": tt.source})
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(violations, "\n")
			if tt.want == "" && got != "" {
				t.Fatalf("violations = %q, want none", got)
			}
			if tt.want != "" && !strings.Contains(got, tt.want) {
				t.Fatalf("violations = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolvedProjectionInvariantProjectionDataProvenance(t *testing.T) {
	cases := []struct{ name, source, want string }{
		{"unrelated helper method is allowed", `package scan
import "github.com/scanoss/crypto-finder/internal/oid"
type node struct{}
func entry(r *oid.ResolvedReport){ _=r; helper() }
func helper(){ var n node; n.Name() }`, ""},
		{"unknown method with tainted findings fails closed", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type node struct{}
func entry(r *oid.ResolvedReport){ var n node; n.Name(r.Findings) }
func Name(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }`, "unresolved-method-call"},
		{"unknown method on tainted receiver fails closed", `package scan
import "github.com/scanoss/crypto-finder/internal/oid"
func entry(r *oid.ResolvedReport){ r.Findings.Name() }`, "unresolved-method-call"},
		{"taint crosses helpers aliases and branch join", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type node struct{}
func entry(r *oid.ResolvedReport, yes bool){ one(r.Findings,yes) }
func one(v []entities.Finding, yes bool){ alias:=v; if yes { alias=v } else { alias=v }; two(alias) }
func two(v []entities.Finding){ var n node; n.Name(v) }`, "unresolved-method-call"},
		{"safe first call does not suppress tainted revisit", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type node struct{}
func entry(r *oid.ResolvedReport){ relay(nil); relay(r.Findings) }
func relay(v []entities.Finding){ var n node; n.Name(v) }`, "unresolved-method-call"},
		{"tainted method never reaches namesake free function", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type node struct{}
func entry(r *oid.ResolvedReport){ var n node; n.Name(r.Findings) }
func Name(v []entities.Finding){ _=&entities.InterimReport{Findings:v} }`, "unresolved-method-call"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := checkResolvedProjectionInvariant(map[string]string{"synthetic.go": tt.source})
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(violations, "\n")
			if tt.want == "" && got != "" {
				t.Fatalf("violations = %q, want none", got)
			}
			if tt.want != "" && !strings.Contains(got, tt.want) {
				t.Fatalf("violations = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolvedProjectionInvariantExpandedProjectionTaint(t *testing.T) {
	cases := []struct{ name, source, want string }{
		{"slice alias carries findings taint", `package scan
import "github.com/scanoss/crypto-finder/internal/oid"
type node struct{}
func entry(r *oid.ResolvedReport){ v:=r.Findings[:]; var n node; n.Name(v) }`, "unresolved-method-call"},
		{"composite field carries findings taint", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type holder struct{ v []entities.Finding }; type node struct{}
func entry(r *oid.ResolvedReport){ h:=holder{v:r.Findings}; var n node; n.Name(h.v) }`, "unresolved-method-call"},
		{"helper result carries tainted argument", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type node struct{}
func identity(v []entities.Finding) []entities.Finding { return v }
func entry(r *oid.ResolvedReport){ v:=identity(r.Findings); var n node; n.Name(v) }`, "unresolved-method-call"},
		{"closure result carries captured findings", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type node struct{}
func entry(r *oid.ResolvedReport){ f:=func() []entities.Finding { return r.Findings }; v:=f(); var n node; n.Name(v) }`, "unresolved-method-call"},
		{"nested aggregate carries findings taint", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type inner struct{ v []entities.Finding }; type outer struct{ i inner }; type node struct{}
func entry(r *oid.ResolvedReport){ h:=outer{i:inner{v:r.Findings}}; var n node; n.Name(h.i.v) }`, "unresolved-method-call"},
		{"chained helper returns carry findings taint", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type node struct{}
func one(v []entities.Finding) []entities.Finding { return v }; func two(v []entities.Finding) []entities.Finding { return v }
func entry(r *oid.ResolvedReport){ v:=two(one(r.Findings)); var n node; n.Name(v) }`, "unresolved-method-call"},
		{"untainted aggregate control is allowed", `package scan
import ("github.com/scanoss/crypto-finder/internal/entities"; "github.com/scanoss/crypto-finder/internal/oid")
type holder struct{ v []entities.Finding }; type node struct{}
func identity(v []entities.Finding) []entities.Finding { return v }
func entry(r *oid.ResolvedReport){ _=r; h:=holder{v:identity(nil)}; var n node; n.Name(h.v) }`, ""},
		{"finding path and line are selector influence", `package scan
import "github.com/scanoss/crypto-finder/internal/oid"
type finding struct{ FilePath string; Line int }; type fragment struct{}
func entry(r *oid.ResolvedReport){ f:=r.Findings[0]; var g fragment; g.ContainingFunction(f.FilePath, f.Line) }`, ""},
		{"influenced slice index does not taint structural element", `package scan
import "github.com/scanoss/crypto-finder/internal/oid"
type edge struct{}; func entry(r *oid.ResolvedReport){ edges:=[]edge{{}}; index:=len(r.Findings); edges[index].view() }`, ""},
		{"influenced slice index does not taint structural method value", `package scan
import "github.com/scanoss/crypto-finder/internal/oid"
type edge struct{}; func entry(r *oid.ResolvedReport){ edges:=[]edge{{}}; index:=len(r.Findings); edges[index].functionName() }`, ""},
		{"object identifiers are selector influence", `package scan
import "github.com/scanoss/crypto-finder/internal/oid"
type selector struct{}; func entry(r *oid.ResolvedReport){ s:=selector{}; object:=string(r.Findings[0].ID); s.selectReceiverCalls("parent",object) }`, ""},
		{"influenced map key does not taint structural value", `package scan
import "github.com/scanoss/crypto-finder/internal/oid"
type keyLength struct{}; func entry(r *oid.ResolvedReport){ values:=map[string]keyLength{}; key:=r.Findings[0].ID; values[key].Clone() }`, ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := checkResolvedProjectionInvariant(map[string]string{"synthetic.go": tt.source})
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(violations, "\n")
			if tt.want == "" && got != "" {
				t.Fatalf("violations = %q, want none", got)
			}
			if tt.want != "" && !strings.Contains(got, tt.want) {
				t.Fatalf("violations = %q, want %q", got, tt.want)
			}
		})
	}
}
