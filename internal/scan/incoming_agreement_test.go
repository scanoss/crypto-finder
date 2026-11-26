package scan

import (
	"reflect"
	"testing"

	"github.com/scanoss/reach/callgraph"
)

// agreeOver feeds sites to an incomingAgreement the way
// resolveIncomingParameterSources does, and counts the sites it resolved.
func agreeOver(sites [][]callgraph.SourceNode) (provenance []callgraph.SourceNode, resolved int) {
	var agreed incomingAgreement
	for _, site := range sites {
		if !agreed.add(func() []callgraph.SourceNode { resolved++; return site }) {
			return nil, resolved
		}
	}
	return agreed.first, resolved
}

func TestIncomingAgreement(t *testing.T) {
	literal := func(v string) []callgraph.SourceNode {
		return []callgraph.SourceNode{{Type: sourceNodeTypeValue, Value: v}}
	}
	variable := []callgraph.SourceNode{{Type: sourceNodeTypeParameter, Name: "x"}}

	tests := []struct {
		name     string
		sites    [][]callgraph.SourceNode
		want     []callgraph.SourceNode
		resolved int
	}{
		{name: "no call site", want: nil, resolved: 0},
		{name: "one call site is the provenance", sites: [][]callgraph.SourceNode{variable}, want: variable, resolved: 1},
		{name: "sites passing one constant agree", sites: [][]callgraph.SourceNode{literal(`"AES"`), literal(`"AES"`), literal(`"AES"`)}, want: literal(`"AES"`), resolved: 3},
		{name: "different constants stop at the second", sites: [][]callgraph.SourceNode{literal(`"AES"`), literal(`"DES"`), literal(`"AES"`)}, want: nil, resolved: 2},
		{name: "an unfolded first site stops before resolving the second", sites: [][]callgraph.SourceNode{variable, literal(`"AES"`), literal(`"AES"`)}, want: nil, resolved: 1},
		{name: "an unfolded later site rules agreement out", sites: [][]callgraph.SourceNode{literal(`"AES"`), variable, literal(`"AES"`)}, want: nil, resolved: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, resolved := agreeOver(tt.sites)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("provenance = %+v, want %+v", got, tt.want)
			}
			if resolved != tt.resolved {
				t.Fatalf("resolved %d call sites, want %d", resolved, tt.resolved)
			}
		})
	}
}
