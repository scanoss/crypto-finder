package callgraph

import (
	"slices"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The AWS SDK v1 verify and MAC request lifecycle keys on the identity the
// Java parser gives each call, in both the fluent withX form and the bean
// setter form AWS's own v1 samples use: construction, key and message,
// signature, algorithm selection, the client operation and the result.
func TestAWSKMSV1VerifyAndMacContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	calls := parseJavaCallArities(t, `package app;

import java.nio.ByteBuffer;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.GenerateMacRequest;
import com.amazonaws.services.kms.model.GenerateMacResult;
import com.amazonaws.services.kms.model.VerifyRequest;
import com.amazonaws.services.kms.model.VerifyResult;

public class App {
    public boolean verify(String keyId, ByteBuffer message, ByteBuffer signature) {
        AWSKMS kms = AWSKMSClientBuilder.defaultClient();
        VerifyRequest request = new VerifyRequest()
            .withKeyId(keyId)
            .withMessage(message)
            .withSignature(signature)
            .withSigningAlgorithm("ECDSA_SHA_256");
        VerifyResult result = kms.verify(request);
        return result.getSignatureValid();
    }

    public boolean verifyBean(AWSKMS kms, String keyId, ByteBuffer message, ByteBuffer signature) {
        VerifyRequest request = new VerifyRequest();
        request.setKeyId(keyId);
        request.setMessage(message);
        request.setSignature(signature);
        request.setSigningAlgorithm("RSASSA_PSS_SHA_256");
        return kms.verify(request).getSignatureValid();
    }

    public ByteBuffer mac(AWSKMS kms, String keyId, ByteBuffer message) {
        GenerateMacRequest request = new GenerateMacRequest()
            .withKeyId(keyId)
            .withMessage(message)
            .withMacAlgorithm("HMAC_SHA_256");
        GenerateMacResult result = kms.generateMac(request);
        return result.getMac();
    }

    public ByteBuffer macBean(AWSKMS kms, String keyId, ByteBuffer message) {
        GenerateMacRequest request = new GenerateMacRequest();
        request.setKeyId(keyId);
        request.setMessage(message);
        request.setMacAlgorithm("HMAC_SHA_512");
        return kms.generateMac(request).getMac();
    }
}
`)

	const pkg = "com.amazonaws.services.kms.model."
	for _, tc := range []struct {
		method string
		arity  int
		role   string
	}{
		{pkg + "VerifyRequest.<init>", 0, "factory"},
		{pkg + "VerifyRequest.withKeyId", 1, "config"},
		{pkg + "VerifyRequest.withMessage", 1, "config"},
		{pkg + "VerifyRequest.withSignature", 1, "config"},
		{pkg + "VerifyRequest.withSigningAlgorithm", 1, "config"},
		{pkg + "VerifyRequest.setKeyId", 1, "config"},
		{pkg + "VerifyRequest.setMessage", 1, "config"},
		{pkg + "VerifyRequest.setSignature", 1, "config"},
		{pkg + "VerifyRequest.setSigningAlgorithm", 1, "config"},
		{pkg + "VerifyResult.getSignatureValid", 0, "output"},
		{pkg + "GenerateMacRequest.<init>", 0, "factory"},
		{pkg + "GenerateMacRequest.withKeyId", 1, "config"},
		{pkg + "GenerateMacRequest.withMessage", 1, "config"},
		{pkg + "GenerateMacRequest.withMacAlgorithm", 1, "config"},
		{pkg + "GenerateMacRequest.setKeyId", 1, "config"},
		{pkg + "GenerateMacRequest.setMessage", 1, "config"},
		{pkg + "GenerateMacRequest.setMacAlgorithm", 1, "config"},
		{pkg + "GenerateMacResult.getMac", 0, "output"},
		{"com.amazonaws.services.kms.AWSKMS.verify", 1, "operation"},
		{"com.amazonaws.services.kms.AWSKMS.generateMac", 1, "operation"},
	} {
		if !slices.Contains(calls[tc.method], tc.arity) {
			t.Errorf("no parsed call to %s with %d argument(s); parsed %v", tc.method, tc.arity, calls[tc.method])
			continue
		}
		got := kb.ContractsForTolerant(tc.method, tc.arity)
		if len(got) != 1 {
			t.Errorf("ContractsForTolerant(%q, %d) = %d, want exactly one", tc.method, tc.arity, len(got))
			continue
		}
		if got[0].Role != tc.role {
			t.Errorf("%s/%d: role = %q, want %q", tc.method, tc.arity, got[0].Role, tc.role)
		}
		if got[0].SourceLibrary != "aws-kms" {
			t.Errorf("%s/%d: library = %q, want aws-kms", tc.method, tc.arity, got[0].SourceLibrary)
		}
	}
}

// Grant tokens and dry runs are request plumbing, not cryptography, so they
// resolve to nothing.
func TestAWSKMSV1VerifyAndMacContractsIgnoreRequestPlumbing(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	calls := parseJavaCallArities(t, `package app;

import com.amazonaws.services.kms.model.GenerateMacRequest;
import com.amazonaws.services.kms.model.VerifyRequest;

public class App {
    public void plumbing(VerifyRequest verify, GenerateMacRequest mac, java.util.List<String> tokens) {
        verify.withGrantTokens(tokens);
        verify.setDryRun(true);
        mac.withDryRun(true);
    }
}
`)

	for _, method := range []string{
		"com.amazonaws.services.kms.model.VerifyRequest.withGrantTokens",
		"com.amazonaws.services.kms.model.VerifyRequest.setDryRun",
		"com.amazonaws.services.kms.model.GenerateMacRequest.withDryRun",
	} {
		arities := calls[method]
		if len(arities) == 0 {
			t.Fatalf("no parsed call to %s; the fixture no longer exercises it", method)
		}
		for _, arity := range arities {
			if got := kb.ContractsForTolerant(method, arity); len(got) != 0 {
				t.Errorf("%s/%d resolved to %d contract(s), want none", method, arity, len(got))
			}
		}
	}
}

// The signing and MAC algorithm setters select the operation in both spellings.
func TestAWSKMSV1VerifyAndMacContractsReportAlgorithm(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	const pkg = "com.amazonaws.services.kms.model."
	for _, method := range []string{
		pkg + "VerifyRequest.withSigningAlgorithm",
		pkg + "VerifyRequest.setSigningAlgorithm",
		pkg + "GenerateMacRequest.withMacAlgorithm",
		pkg + "GenerateMacRequest.setMacAlgorithm",
	} {
		got := kb.ContractsForTolerant(method, 1)
		if len(got) != 1 {
			t.Errorf("ContractsForTolerant(%q, 1) = %d, want exactly one", method, len(got))
			continue
		}
		params := got[0].Parameters
		if len(params) != 1 || params[0].Index == nil || *params[0].Index != 0 ||
			params[0].Role != "operation-determining" || params[0].Contributes == nil ||
			params[0].Contributes.Property != "algorithm" {
			t.Errorf("%s/1: parameters = %#v, want index 0 operation-determining algorithm", method, params)
		}
	}
}
