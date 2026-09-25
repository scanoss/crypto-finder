package callgraph

import (
	"slices"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// azureKeyVaultKeyOptionsAndCertificatesConsumer walks the key options and the
// certificate lifecycle the crypto_rules fixtures exercise: typed option
// setters, the certificate client builder, a policy, creation through the
// poller and import.
const azureKeyVaultKeyOptionsAndCertificatesConsumer = `
package app;

import com.azure.core.util.Context;
import com.azure.core.util.polling.SyncPoller;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.certificates.CertificateAsyncClient;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.CertificateKeyCurveName;
import com.azure.security.keyvault.certificates.models.CertificateKeyType;
import com.azure.security.keyvault.certificates.models.CertificateOperation;
import com.azure.security.keyvault.certificates.models.CertificatePolicy;
import com.azure.security.keyvault.certificates.models.CreateCertificateOptions;
import com.azure.security.keyvault.certificates.models.ImportCertificateOptions;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.models.CreateEcKeyOptions;
import com.azure.security.keyvault.keys.models.CreateKeyOptions;
import com.azure.security.keyvault.keys.models.CreateOctKeyOptions;
import com.azure.security.keyvault.keys.models.CreateRsaKeyOptions;
import com.azure.security.keyvault.keys.models.KeyCurveName;
import com.azure.security.keyvault.keys.models.KeyType;
import com.azure.security.keyvault.keys.models.KeyVaultKey;

public class App {
    public KeyVaultKey rsa(KeyClient keys) {
        CreateRsaKeyOptions options = new CreateRsaKeyOptions("signing-key");
        options.setKeySize(3072);
        return keys.createRsaKey(options);
    }

    public KeyVaultKey ec(KeyClient keys) {
        CreateEcKeyOptions options = new CreateEcKeyOptions("ec-key");
        options.setCurveName(KeyCurveName.P_384);
        return keys.createEcKey(options);
    }

    public KeyVaultKey oct(KeyClient keys) {
        CreateOctKeyOptions options = new CreateOctKeyOptions("wrap-key");
        options.setKeySize(256);
        return keys.createOctKey(options);
    }

    public KeyVaultKey generic(KeyClient keys) {
        CreateKeyOptions options = new CreateKeyOptions("generic-key", KeyType.RSA);
        return keys.createKey(options);
    }

    public KeyVaultCertificateWithPolicy create(String vaultUrl) {
        CertificateClient client = new CertificateClientBuilder()
            .vaultUrl(vaultUrl)
            .credential(new DefaultAzureCredentialBuilder().build())
            .buildClient();
        CertificatePolicy policy = new CertificatePolicy("Self", "CN=example.com");
        policy.setKeyType(CertificateKeyType.EC);
        policy.setKeyCurveName(CertificateKeyCurveName.P_256);
        SyncPoller<CertificateOperation, KeyVaultCertificateWithPolicy> poller =
            client.beginCreateCertificate("example-cert", policy);
        return poller.getFinalResult();
    }

    public KeyVaultCertificateWithPolicy createRsa(CertificateClient client) {
        CertificatePolicy policy = CertificatePolicy.getDefault();
        policy.setKeyType(CertificateKeyType.RSA);
        policy.setKeySize(4096);
        SyncPoller<CertificateOperation, KeyVaultCertificateWithPolicy> poller =
            client.beginCreateCertificate("rsa-cert", policy, true, null);
        return poller.getFinalResult();
    }

    public KeyVaultCertificateWithPolicy createFromOptions(CertificateClient client) {
        CreateCertificateOptions options = new CreateCertificateOptions("opt-cert", CertificatePolicy.getDefault());
        SyncPoller<CertificateOperation, KeyVaultCertificateWithPolicy> poller = client.beginCreateCertificate(options);
        return poller.getFinalResult();
    }

    public KeyVaultCertificateWithPolicy importPfx(CertificateClient client, byte[] pfx) {
        ImportCertificateOptions options = new ImportCertificateOptions("imported", pfx);
        client.importCertificateWithResponse(options, Context.NONE);
        return client.importCertificate(options);
    }

    public void importAsync(CertificateAsyncClient client, byte[] pfx) {
        client.importCertificate(new ImportCertificateOptions("imported-async", pfx)).block();
    }
}
`

// Each call keys on the identity the Java parser gives it and resolves to
// exactly one contract, with its role, in the file that claims the releases
// where the API exists.
func TestAzureKeyVaultKeyOptionsAndCertificatesResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}
	calls := parseJavaCallArities(t, azureKeyVaultKeyOptionsAndCertificatesConsumer)

	const (
		keys    = "com.azure.security.keyvault.keys.models."
		certs   = "com.azure.security.keyvault.certificates."
		polling = "com.azure.core.util.polling."
	)
	for _, tc := range []struct {
		method  string
		arity   int
		role    string
		library string
	}{
		{keys + "CreateKeyOptions.<init>", 2, "factory", "azure-keyvault-keys-java"},
		{keys + "CreateRsaKeyOptions.<init>", 1, "factory", "azure-keyvault-keys-java"},
		{keys + "CreateRsaKeyOptions.setKeySize", 1, "config", "azure-keyvault-keys-java"},
		{keys + "CreateEcKeyOptions.<init>", 1, "factory", "azure-keyvault-keys-java"},
		{keys + "CreateEcKeyOptions.setCurveName", 1, "config", "azure-keyvault-keys-java"},
		{keys + "CreateOctKeyOptions.<init>", 1, "factory", "azure-keyvault-keys-java-4.3"},
		{keys + "CreateOctKeyOptions.setKeySize", 1, "config", "azure-keyvault-keys-java-4.3"},
		{certs + "CertificateClientBuilder.<init>", 0, "factory", "azure-keyvault-certificates-java"},
		{certs + "CertificateClientBuilder.vaultUrl", 1, "config", "azure-keyvault-certificates-java"},
		{certs + "CertificateClientBuilder.credential", 1, "config", "azure-keyvault-certificates-java"},
		{certs + "CertificateClientBuilder.buildClient", 0, "factory", "azure-keyvault-certificates-java"},
		{certs + "models.CertificatePolicy.<init>", 2, "factory", "azure-keyvault-certificates-java"},
		{certs + "models.CertificatePolicy.getDefault", 0, "factory", "azure-keyvault-certificates-java"},
		{certs + "models.CertificatePolicy.setKeyType", 1, "config", "azure-keyvault-certificates-java"},
		{certs + "models.CertificatePolicy.setKeySize", 1, "config", "azure-keyvault-certificates-java"},
		{certs + "models.CertificatePolicy.setKeyCurveName", 1, "config", "azure-keyvault-certificates-java"},
		{certs + "CertificateClient.beginCreateCertificate", 2, "operation", "azure-keyvault-certificates-java"},
		{certs + "CertificateClient.beginCreateCertificate", 4, "operation", "azure-keyvault-certificates-java"},
		{certs + "CertificateClient.beginCreateCertificate", 1, "operation", "azure-keyvault-certificates-java-4.8"},
		{certs + "models.CreateCertificateOptions.<init>", 2, "factory", "azure-keyvault-certificates-java-4.8"},
		{polling + "SyncPoller.getFinalResult", 0, "output", "azure-keyvault-certificates-java"},
		{certs + "models.ImportCertificateOptions.<init>", 2, "factory", "azure-keyvault-certificates-java"},
		{certs + "CertificateClient.importCertificate", 1, "operation", "azure-keyvault-certificates-java"},
		{certs + "CertificateClient.importCertificateWithResponse", 2, "operation", "azure-keyvault-certificates-java"},
		{certs + "CertificateAsyncClient.importCertificate", 1, "operation", "azure-keyvault-certificates-java"},
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
		if got[0].SourceLibrary != tc.library {
			t.Errorf("%s/%d: library = %q, want %q", tc.method, tc.arity, got[0].SourceLibrary, tc.library)
		}
	}
}

// The first argument of each key setter carries the key type, size or curve.
func TestAzureKeyVaultKeySettersReportTheirArgument(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	const (
		keys  = "com.azure.security.keyvault.keys.models."
		certs = "com.azure.security.keyvault.certificates.models."
	)
	for _, tc := range []struct {
		method   string
		arity    int
		index    int
		role     string
		property string
	}{
		{keys + "CreateKeyOptions.<init>", 2, 1, "operation-determining", "keyType"},
		{keys + "CreateRsaKeyOptions.setKeySize", 1, 0, "metadata-contributing", "keySize"},
		{keys + "CreateOctKeyOptions.setKeySize", 1, 0, "metadata-contributing", "keySize"},
		{keys + "CreateEcKeyOptions.setCurveName", 1, 0, "metadata-contributing", "curve"},
		{certs + "CertificatePolicy.setKeyType", 1, 0, "operation-determining", "keyType"},
		{certs + "CertificatePolicy.setKeySize", 1, 0, "metadata-contributing", "keySize"},
		{certs + "CertificatePolicy.setKeyCurveName", 1, 0, "metadata-contributing", "curve"},
	} {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) != 1 || len(got[0].Parameters) != 1 {
			t.Errorf("%s#%d = %#v, want one contract with one parameter role", tc.method, tc.arity, got)
			continue
		}
		p := got[0].Parameters[0]
		if p.Index == nil || *p.Index != tc.index || p.Role != tc.role || p.Contributes == nil ||
			p.Contributes.Property != tc.property || p.Contributes.Derivation != "argument_value" {
			t.Errorf("%s#%d parameter = %#v, want index %d %s %s/argument_value", tc.method, tc.arity, p, tc.index, tc.role, tc.property)
		}
	}
}
