package callgraph

import "testing"

func TestBaseFunctionNameAndMethodArityKey(t *testing.T) {
	tests := []struct {
		name         string
		wantArityKey string
		wantBaseName string
	}{
		{name: "encrypt#1", wantArityKey: "encrypt#1", wantBaseName: "encrypt"},
		{name: "signWith#2$SignatureAlgorithm,byte[]", wantArityKey: "signWith#2", wantBaseName: "signWith"},
		{name: "plain", wantArityKey: "plain", wantBaseName: "plain"},
		{name: "#broken", wantArityKey: "#broken", wantBaseName: "#broken"},
		{name: "name#", wantArityKey: "name#", wantBaseName: "name"},
		{name: "name#abc", wantArityKey: "name#abc", wantBaseName: "name"},
	}

	for _, tt := range tests {
		if got := methodArityKey(tt.name); got != tt.wantArityKey {
			t.Fatalf("methodArityKey(%q) = %q, want %q", tt.name, got, tt.wantArityKey)
		}
		if got := BaseFunctionName(tt.name); got != tt.wantBaseName {
			t.Fatalf("BaseFunctionName(%q) = %q, want %q", tt.name, got, tt.wantBaseName)
		}
	}
}

func TestFunctionID_String(t *testing.T) {
	method := FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "getInstance#1"}
	if got := method.String(); got != "javax.crypto.(Cipher).getInstance#1" {
		t.Fatalf("method.String() = %q", got)
	}

	fn := FunctionID{Package: "crypto/aes", Name: "NewCipher"}
	if got := fn.String(); got != "crypto/aes.NewCipher" {
		t.Fatalf("fn.String() = %q", got)
	}
}
