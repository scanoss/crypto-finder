package cardmatch

// YAML loading with PyYAML's yaml.safe_load semantics (YAML 1.1), which is what match2.py uses.
//
// yaml.v3 parses the document (anchors and aliases included); the values are then built from the
// node tree here, so that:
//   - plain scalars resolve the way PyYAML resolves them (yes/no/on/off are booleans, 1.1 integer
//     and float forms, ~ and empty are null), not the YAML 1.2 way yaml.v3 would;
//   - mappings keep their key order (match2.py iterates a value pattern's keys in document order);
//   - merge keys (`<<: *anchor`) are flattened the way PyYAML's flatten_mapping does (merged keys
//     first, explicit keys override them in place).
//
// Values: string, int64 / *big.Int, float64, bool, nil, []any, *OMap.

import (
	"fmt"
	"math"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// OMap is a mapping with the key order of the document. Keys are typed scalars.
type OMap struct {
	Keys []any
	Vals []any
}

func (m *OMap) index(k any) int {
	for i, x := range m.Keys {
		if scalarEq(x, k) {
			return i
		}
	}
	return -1
}

// Set assigns like a Python dict: an existing key keeps its position.
func (m *OMap) Set(k, v any) {
	if i := m.index(k); i >= 0 {
		m.Vals[i] = v
		return
	}
	m.Keys = append(m.Keys, k)
	m.Vals = append(m.Vals, v)
}

// Get looks up a string key.
func (m *OMap) Get(k string) (any, bool) {
	if m == nil {
		return nil, false
	}
	for i, x := range m.Keys {
		if s, ok := x.(string); ok && s == k {
			return m.Vals[i], true
		}
	}
	return nil, false
}

// Has reports whether the key is present.
func (m *OMap) Has(k string) bool {
	_, ok := m.Get(k)
	return ok
}

// GetOr returns the value or nil.
func (m *OMap) GetOr(k string) any {
	v, _ := m.Get(k)
	return v
}

// Len is the number of keys, 0 for a nil map.
func (m *OMap) Len() int {
	if m == nil {
		return 0
	}
	return len(m.Keys)
}

func scalarEq(a, b any) bool {
	switch x := a.(type) {
	case *big.Int:
		if y, ok := b.(*big.Int); ok {
			return x.Cmp(y) == 0
		}
		return false
	case []any, *OMap:
		return false
	}
	switch b.(type) {
	case []any, *OMap, *big.Int:
		return false
	}
	// Python: True == 1 and 1 == 1.0 as dict keys; the data never mixes them, so plain equality.
	return a == b
}

// PyYAML's implicit resolvers (resolver.py), applied to plain scalars only.
var (
	yBool  = regexp.MustCompile(`^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$`)
	yFloat = regexp.MustCompile(`^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$`)
	yInt   = regexp.MustCompile(`^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$`)
	yNull  = regexp.MustCompile(`^(?:~|null|Null|NULL|)$`)
	yTime  = regexp.MustCompile(`^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$`)
)

func resolvePlain(s string) any {
	if s == "" {
		return nil
	}
	switch {
	case yBool.MatchString(s):
		switch strings.ToLower(s) {
		case "yes", "true", "on":
			return true
		}
		return false
	case yInt.MatchString(s):
		return constructInt(s)
	case yFloat.MatchString(s):
		return constructFloat(s)
	case yNull.MatchString(s):
		return nil
	case yTime.MatchString(s):
		// PyYAML builds a date/datetime; no card or rule metadata has one. Kept as text, flagged.
		panic(fmt.Sprintf("yaml timestamp scalar %q is not supported", s))
	}
	return s
}

func constructInt(s string) any {
	v := strings.ReplaceAll(s, "_", "")
	sign := int64(1)
	if v[0] == '-' {
		sign = -1
	}
	if v[0] == '+' || v[0] == '-' {
		v = v[1:]
	}
	n := new(big.Int)
	switch {
	case v == "0":
		return int64(0)
	case strings.HasPrefix(v, "0b"):
		n.SetString(v[2:], 2)
	case strings.HasPrefix(v, "0x"):
		n.SetString(v[2:], 16)
	case v[0] == '0':
		n.SetString(v, 8)
	case strings.Contains(v, ":"):
		base := big.NewInt(1)
		for _, part := range reverse(strings.Split(v, ":")) {
			d := lenient(strconv.ParseInt(part, 10, 64))
			n.Add(n, new(big.Int).Mul(big.NewInt(d), base))
			base.Mul(base, big.NewInt(60))
		}
	default:
		n.SetString(v, 10)
	}
	n.Mul(n, big.NewInt(sign))
	if n.IsInt64() {
		return n.Int64()
	}
	return n
}

func reverse(xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[len(xs)-1-i] = x
	}
	return out
}

func constructFloat(s string) any {
	v := strings.ToLower(strings.ReplaceAll(s, "_", ""))
	sign := 1.0
	if v[0] == '-' {
		sign = -1
	}
	if v[0] == '+' || v[0] == '-' {
		v = v[1:]
	}
	switch {
	case v == ".inf":
		return sign * math.Inf(1)
	case v == ".nan":
		return math.NaN()
	case strings.Contains(v, ":"):
		parts := reverse(strings.Split(v, ":"))
		base, total := 1.0, 0.0
		for _, p := range parts {
			f := lenient(strconv.ParseFloat(p, 64))
			total += f * base
			base *= 60
		}
		return sign * total
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		panic(fmt.Sprintf("yaml float %q: %v", s, err))
	}
	return sign * f
}

// loadYAML is yaml.safe_load(open(path)): nil for an empty document.
func loadYAML(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v, err := memoYAML(parseMemoFor(path), data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}

func parseYAML(data []byte) (any, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		return nil, nil
	}
	return buildNode(doc.Content[0]), nil
}

func isPlain(n *yaml.Node) bool {
	return n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) == 0
}

func buildNode(n *yaml.Node) any {
	switch n.Kind {
	case yaml.AliasNode:
		return buildNode(n.Alias)
	case yaml.ScalarNode:
		if n.Style&yaml.TaggedStyle != 0 {
			switch n.Tag {
			case "!!str":
				return n.Value
			case "!!int":
				return constructInt(n.Value)
			case "!!float":
				return constructFloat(n.Value)
			case "!!bool":
				return resolvePlain(n.Value)
			case "!!null":
				return nil
			}
			panic("unsupported yaml tag " + n.Tag)
		}
		if isPlain(n) {
			return resolvePlain(n.Value)
		}
		return n.Value
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			out = append(out, buildNode(c))
		}
		return out
	case yaml.MappingNode:
		m := &OMap{}
		for _, kv := range flattenMapping(n) {
			m.Set(buildNode(kv[0]), buildNode(kv[1]))
		}
		return m
	case yaml.DocumentNode:
		// Not a value node: the panic below reports it.
	}
	panic(fmt.Sprintf("unsupported yaml node kind %d", n.Kind))
}

func deref(n *yaml.Node) *yaml.Node {
	for n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// flattenMapping is PyYAML's SafeConstructor.flatten_mapping: the pairs of the merged mappings
// come first (for a sequence of mappings, the last one first), then the mapping's own pairs.
func flattenMapping(n *yaml.Node) [][2]*yaml.Node {
	var merge, own [][2]*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind == yaml.ScalarNode && k.Value == "<<" && isPlain(k) {
			v = deref(v)
			switch v.Kind {
			case yaml.MappingNode:
				merge = append(merge, flattenMapping(v)...)
			case yaml.SequenceNode:
				var subs [][][2]*yaml.Node
				for _, s := range v.Content {
					subs = append(subs, flattenMapping(deref(s)))
				}
				for j := len(subs) - 1; j >= 0; j-- {
					merge = append(merge, subs[j]...)
				}
			case yaml.DocumentNode, yaml.ScalarNode, yaml.AliasNode:
				panic("bad merge value")
			}
			continue
		}
		own = append(own, [2]*yaml.Node{k, v})
	}
	return append(merge, own...)
}

// --- Python value helpers ------------------------------------------------------------------------

// pyStr is Python's str() of a loaded value.
func pyStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case int64:
		return strconv.FormatInt(x, 10)
	case *big.Int:
		return x.String()
	case float64:
		return pyFloatRepr(x)
	case jsonNumber:
		return pyJSONNumberStr(string(x))
	}
	return pyRepr(v)
}

func pyRepr(v any) string {
	switch x := v.(type) {
	case string:
		return pyStrRepr(x)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = pyRepr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *OMap:
		parts := make([]string, len(x.Keys))
		for i := range x.Keys {
			parts[i] = pyRepr(x.Keys[i]) + ": " + pyRepr(x.Vals[i])
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return pyStr(v)
}

func pyStrRepr(s string) string {
	q := "'"
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		q = `"`
	}
	var b strings.Builder
	b.WriteString(q)
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case string(r) == q:
			b.WriteString(`\` + q)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteString(q)
	return b.String()
}

// pyFloatRepr is repr(float): shortest round-trip digits, Python's exponent rules.
func pyFloatRepr(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	case math.IsNaN(f):
		return "nan"
	}
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	exp := math.Floor(math.Log10(math.Abs(f)))
	if exp >= 16 || exp < -4 {
		return strconv.FormatFloat(f, 'e', -1, 64) // 1e+16, 1e-05: the same text as Python
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}

// pyTruthy is bool(v).
func pyTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case int64:
		return x != 0
	case *big.Int:
		return x.Sign() != 0
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case *OMap:
		return x.Len() > 0
	case jsonNumber:
		f := lenient(strconv.ParseFloat(string(x), 64))
		return f != 0
	}
	return true
}

// asList is match2.as_list: a list stays, anything else becomes a one-element list.
func asList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return []any{v}
}

// pyInt is int(v) for an int or a decimal string.
func pyInt(v any) int {
	switch x := v.(type) {
	case int64:
		return int(x)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		if err != nil {
			panic(fmt.Sprintf("int(%q)", x))
		}
		return n
	case bool:
		if x {
			return 1
		}
		return 0
	}
	panic(fmt.Sprintf("int(%v)", v))
}
