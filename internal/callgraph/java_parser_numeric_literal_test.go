package callgraph

import "testing"

func TestIsNumericLiteral(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "decimal integer", input: "42", want: true},
		{name: "negative decimal integer", input: "-42", want: true},
		{name: "decimal float", input: "3.14", want: true},
		{name: "leading decimal point", input: ".5", want: true},
		{name: "negative leading decimal point", input: "-.5", want: true},
		{name: "decimal suffix", input: "1f", want: true},
		{name: "decimal long suffix", input: "1L", want: true},
		{name: "hex with digit", input: "0x1f", want: true},
		{name: "negative hex with digit", input: "-0XDEAD1", want: true},
		{name: "empty", input: "", want: false},
		{name: "minus only", input: "-", want: false},
		{name: "dot only", input: ".", want: false},
		{name: "identifier face", input: "face", want: false},
		{name: "identifier dead", input: "dead", want: false},
		{name: "decimal with hex letters", input: "1a", want: false},
		{name: "hex prefix only", input: "0x", want: false},
		{name: "hex without decimal digit", input: "0xFF", want: false},
		{name: "multiple dots", input: "1.2.3", want: false},
		{name: "suffix not at end", input: "1f2", want: false},
		{name: "hex suffix", input: "0x1L", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNumericLiteral(tt.input); got != tt.want {
				t.Fatalf("isNumericLiteral(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestTraceLiteralExpression_DoesNotTreatIdentifiersAsNumericLiterals(t *testing.T) {
	if got := traceLiteralExpression("face"); got != nil {
		t.Fatalf("traceLiteralExpression(%q) = %#v, want nil", "face", got)
	}

	if got := traceLiteralExpression("dead"); got != nil {
		t.Fatalf("traceLiteralExpression(%q) = %#v, want nil", "dead", got)
	}
}
