package contracts_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedJavaIncludesPassword4JAndBouncyCastleContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	passwordHash := kb.ContractsFor("com.password4j.Password.hash", 1)
	if len(passwordHash) != 1 {
		t.Fatalf("Password.hash#1 contracts = %d, want 1", len(passwordHash))
	}
	if passwordHash[0].Return.Type != "com.password4j.HashBuilder" || passwordHash[0].SourceLibrary != "password4j" {
		t.Fatalf("Password.hash#1 = %#v, want com.password4j.HashBuilder from password4j", passwordHash[0])
	}

	// Casing must match Password4J's real API (withBcrypt/withScrypt, lowercase
	// c/s); contracts match on exact Method#Arity so the casing is load-bearing.
	for _, method := range []string{
		"com.password4j.HashBuilder.withBcrypt",
		"com.password4j.HashBuilder.withScrypt",
		"com.password4j.HashBuilder.withPBKDF2",
		"com.password4j.HashBuilder.withCompressedPBKDF2",
		"com.password4j.HashBuilder.withArgon2",
		"com.password4j.HashBuilder.withMessageDigest",
	} {
		got := kb.ContractsFor(method, 0)
		if len(got) != 1 {
			t.Fatalf("%s#0 contracts = %d, want 1", method, len(got))
		}
		if got[0].Return.Type != "com.password4j.Hash" || got[0].SourceLibrary != "password4j" {
			t.Fatalf("%s#0 = %#v, want com.password4j.Hash from password4j", method, got[0])
		}
	}

	bcKeyPair := kb.ContractsFor("org.bouncycastle.crypto.generators.ECKeyPairGenerator.generateKeyPair", 0)
	if len(bcKeyPair) != 1 {
		t.Fatalf("ECKeyPairGenerator.generateKeyPair#0 contracts = %d, want 1", len(bcKeyPair))
	}
	if bcKeyPair[0].Return.Type != "org.bouncycastle.crypto.AsymmetricCipherKeyPair" || bcKeyPair[0].SourceLibrary != "bouncycastle" {
		t.Fatalf("ECKeyPairGenerator.generateKeyPair#0 = %#v, want AsymmetricCipherKeyPair from bouncycastle", bcKeyPair[0])
	}
}

func TestLoadEmbeddedJavaIncludesTier0GapContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	tests := []struct {
		method     string
		arity      int
		wantReturn string
		wantLib    string
	}{
		{"io.jsonwebtoken.Jwts.builder", 0, "io.jsonwebtoken.JwtBuilder", "jjwt"},
		{"io.jsonwebtoken.JwtBuilder.signWith", 1, "io.jsonwebtoken.JwtBuilder", "jjwt"},
		{"io.jsonwebtoken.JwtParserBuilder.build", 0, "io.jsonwebtoken.JwtParser", "jjwt"},
		{"io.jsonwebtoken.JwtParser.parseSignedClaims", 1, "io.jsonwebtoken.Jws", "jjwt"},
		{"com.nimbusds.jose.JWSObject.<init>", 2, "com.nimbusds.jose.JWSObject", "nimbus-jose-jwt"},
		{"com.nimbusds.jose.JWSObject.verify", 1, "boolean", "nimbus-jose-jwt"},
		{"com.nimbusds.jose.crypto.RSASSASigner.sign", 2, "com.nimbusds.jose.util.Base64URL", "nimbus-jose-jwt"},
		{"com.nimbusds.jose.crypto.DirectEncrypter.<init>", 1, "com.nimbusds.jose.crypto.DirectEncrypter", "nimbus-jose-jwt"},
		{"com.nimbusds.jose.crypto.ECDSASigner.<init>", 1, "com.nimbusds.jose.crypto.ECDSASigner", "nimbus-jose-jwt"},
		{"com.nimbusds.jose.crypto.MACVerifier.<init>", 1, "com.nimbusds.jose.crypto.MACVerifier", "nimbus-jose-jwt"},
		{"org.apache.sshd.common.config.keys.KeyUtils.generateKeyPair", 2, "java.security.KeyPair", "apache-sshd"},
		{"org.apache.sshd.common.cipher.BuiltinCiphers.resolveFactory", 1, "org.apache.sshd.common.cipher.CipherFactory", "apache-sshd"},
		{"org.apache.sshd.common.mac.BuiltinMacs.create", 0, "org.apache.sshd.common.mac.Mac", "apache-sshd"},
		{"org.apache.sshd.common.signature.BuiltinSignatures.create", 0, "org.apache.sshd.common.signature.Signature", "apache-sshd"},
		{"org.apache.sshd.client.SshClient.setUpDefaultClient", 0, "org.apache.sshd.client.SshClient", "apache-sshd"},
		{"org.apache.sshd.server.SshServer.setUpDefaultServer", 0, "org.apache.sshd.server.SshServer", "apache-sshd"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].Return.Type != tt.wantReturn || got[0].SourceLibrary != tt.wantLib {
				t.Fatalf("%s#%d = %#v, want %s from %s", tt.method, tt.arity, got[0], tt.wantReturn, tt.wantLib)
			}
		})
	}
}

func TestLoadEmbeddedJavaIncludesIssue138LifecycleContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	tests := []struct {
		method     string
		arity      int
		wantReturn string
		wantRole   string
		wantLib    string
	}{
		{"org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.<init>", 1, "org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder", "factory", "bouncycastle-openpgp"},
		{"org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.getAlgorithm", 0, "int", "output", "bouncycastle-openpgp"},
		{"org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder.build", 1, "org.bouncycastle.openpgp.operator.PGPDataEncryptor", "factory", "bouncycastle-openpgp"},
		{"org.bouncycastle.openpgp.PGPEncryptedDataGenerator.open", 2, "java.io.OutputStream", "operation", "bouncycastle-openpgp"},
		{"com.google.crypto.tink.KeysetHandle.generateNew", 1, "com.google.crypto.tink.KeysetHandle", "factory", "tink"},
		{"com.google.crypto.tink.Aead.encrypt", 2, "byte[]", "operation", "tink"},
		{"com.google.crypto.tink.Aead.decrypt", 2, "byte[]", "operation", "tink"},
		{"org.apache.xml.security.encryption.XMLCipher.getInstance", 1, "org.apache.xml.security.encryption.XMLCipher", "factory", "apache-santuario-xmlsec"},
		{"org.apache.xml.security.encryption.XMLCipher.init", 2, "void", "config", "apache-santuario-xmlsec"},
		{"org.apache.xml.security.encryption.XMLCipher.doFinal", 2, "org.w3c.dom.Document", "operation", "apache-santuario-xmlsec"},
		{"org.apache.xml.security.encryption.XMLCipher.doFinal", 3, "org.w3c.dom.Document", "operation", "apache-santuario-xmlsec"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].Return.Type != tt.wantReturn || got[0].Role != tt.wantRole || got[0].SourceLibrary != tt.wantLib {
				t.Fatalf("%s#%d = %#v, want return %s, role %s, library %s", tt.method, tt.arity, got[0], tt.wantReturn, tt.wantRole, tt.wantLib)
			}
		})
	}
}

// TestLoadEmbeddedJava_BouncyCastleRoleCoverage is the issue-103 (WU1/BC-YAML)
// acceptance test scoped to what a unit test can verify without a real BC
// corpus (see internal/scan/bcprov_fragment_profile_test.go for the
// env-gated full-corpus harness): every newly-authored role-tagged BC
// contract loads with the expected role, and processBlock/doFinal/update
// resolve as role: operation via the primitive-family interfaces rather
// than per-engine duplication.
func TestLoadEmbeddedJava_BouncyCastleRoleCoverage(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		role   string
	}{
		{"org.bouncycastle.crypto.params.KeyParameter.<init>", 1, "factory"},
		{"org.bouncycastle.crypto.params.ParametersWithIV.<init>", 2, "factory"},
		{"org.bouncycastle.crypto.params.ParametersWithRandom.<init>", 2, "factory"},
		{"org.bouncycastle.crypto.params.AEADParameters.getNonce", 0, "output"},
		{"org.bouncycastle.crypto.params.AEADParameters.getAssociatedText", 0, "output"},
		{"org.bouncycastle.crypto.params.AEADParameters.getMacSize", 0, "output"},
		{"org.bouncycastle.crypto.params.KeyParameter.getKey", 0, "output"},
		{"org.bouncycastle.crypto.BlockCipher.processBlock", 4, "operation"},
		{"org.bouncycastle.crypto.Digest.update", 1, "operation"},
		{"org.bouncycastle.crypto.Digest.update", 3, "operation"},
		{"org.bouncycastle.crypto.Digest.doFinal", 2, "operation"},
		{"org.bouncycastle.crypto.Signer.generateSignature", 0, "operation"},
		{"org.bouncycastle.crypto.Signer.verifySignature", 1, "operation"},
		{"org.bouncycastle.crypto.Mac.doFinal", 2, "operation"},
		{"org.bouncycastle.crypto.DerivationFunction.generateBytes", 3, "operation"},
		// Corrected from role: config (feeding data into a running digest is
		// the operation itself, not object configuration).
		{"org.bouncycastle.crypto.digests.GeneralDigest.update", 3, "operation"},
		{"org.bouncycastle.crypto.digests.KeccakDigest.update", 3, "operation"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].Role != tt.role {
				t.Fatalf("%s#%d role = %q, want %q", tt.method, tt.arity, got[0].Role, tt.role)
			}
		})
	}

	// KeyParameter.<init>'s byte[] key argument contributes keySize via
	// argument_bit_length (the WU3 concrete target from the design).
	kp := kb.ContractsFor("org.bouncycastle.crypto.params.KeyParameter.<init>", 1)
	if len(kp) != 1 || len(kp[0].Parameters) != 1 {
		t.Fatalf("KeyParameter.<init>#1 parameters = %#v, want 1 entry", kp)
	}
	p := kp[0].Parameters[0]
	if p.Index == nil || *p.Index != 0 || p.Role != "metadata-contributing" ||
		p.Contributes == nil || p.Contributes.Property != "keySize" || p.Contributes.Derivation != "argument_bit_length" {
		t.Fatalf("KeyParameter.<init>#1 parameters[0] = %#v, want index=0 metadata-contributing keySize/argument_bit_length", p)
	}

	// AESEngine implements BlockCipher, so the interface-level processBlock
	// contract is reachable via hierarchy without a per-engine duplicate.
	if parents := kb.Hierarchy["org.bouncycastle.crypto.engines.AESEngine"]; len(parents) != 1 || parents[0] != "org.bouncycastle.crypto.BlockCipher" {
		t.Fatalf("AESEngine hierarchy = %v, want [BlockCipher]", parents)
	}
}

func TestLoadEmbeddedJava_NimbusAndSpringLifecycleCoverage(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		want   string
		role   string
	}{
		{"com.nimbusds.jose.JWEObject.<init>", 2, "com.nimbusds.jose.JWEObject", "factory"},
		{"com.nimbusds.jose.JWEObject.encrypt", 1, "void", "operation"},
		{"com.nimbusds.jose.JWEObject.decrypt", 1, "void", "operation"},
		{"com.nimbusds.jose.JWEEncrypter.encrypt", 3, "com.nimbusds.jose.JWECryptoParts", "operation"},
		{"com.nimbusds.jose.JWEDecrypter.decrypt", 6, "byte[]", "operation"},
		{"com.nimbusds.jose.jwk.gen.RSAKeyGenerator.<init>", 1, "com.nimbusds.jose.jwk.gen.RSAKeyGenerator", "factory"},
		{"org.springframework.security.crypto.password.PasswordEncoder.encode", 1, "java.lang.String", "operation"},
		{"org.springframework.security.crypto.password.PasswordEncoder.matches", 2, "boolean", "operation"},
		{"org.springframework.security.crypto.encrypt.Encryptors.stronger", 2, "org.springframework.security.crypto.encrypt.BytesEncryptor", "factory"},
		{"org.springframework.security.crypto.encrypt.RsaSecretEncryptor.<init>", 0, "org.springframework.security.crypto.encrypt.RsaSecretEncryptor", "factory"},
		{"org.springframework.security.crypto.encrypt.BytesEncryptor.encrypt", 1, "byte[]", "operation"},
		{"org.springframework.security.crypto.encrypt.BytesEncryptor.decrypt", 1, "byte[]", "operation"},
		{"org.springframework.security.crypto.encrypt.TextEncryptor.encrypt", 1, "java.lang.String", "operation"},
		{"org.springframework.security.crypto.encrypt.TextEncryptor.decrypt", 1, "java.lang.String", "operation"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].Return.Type != tt.want || got[0].Role != tt.role {
				t.Fatalf("%s#%d = %#v, want return %q with role %q", tt.method, tt.arity, got[0], tt.want, tt.role)
			}
		})
	}

	rsaGenerator := kb.ContractsFor("com.nimbusds.jose.jwk.gen.RSAKeyGenerator.<init>", 1)
	if len(rsaGenerator) != 1 || len(rsaGenerator[0].Parameters) != 1 {
		t.Fatalf("RSAKeyGenerator.<init>#1 parameters = %#v, want key-size parameter role", rsaGenerator)
	}
	p := rsaGenerator[0].Parameters[0]
	if p.Index == nil || *p.Index != 0 || p.Role != "metadata-contributing" || p.Contributes == nil || p.Contributes.Property != "keySize" || p.Contributes.Derivation != "argument_value" {
		t.Fatalf("RSAKeyGenerator.<init>#1 parameters[0] = %#v, want index=0 keySize/argument_value", p)
	}

	if parents := kb.Hierarchy["org.springframework.security.crypto.encrypt.RsaSecretEncryptor"]; len(parents) != 2 || parents[0] != "org.springframework.security.crypto.encrypt.BytesEncryptor" || parents[1] != "org.springframework.security.crypto.encrypt.TextEncryptor" {
		t.Fatalf("RsaSecretEncryptor hierarchy = %v, want BytesEncryptor and TextEncryptor", parents)
	}
}

// TestLoadEmbeddedJava_NettyTLSBuilderLifecycle verifies the Netty
// SslContextBuilder fluent lifecycle contracts (scanoss/crypto-finder#183):
// forClient/forServer factories, the self-returning fluent configuration
// methods (sslProvider, protocols, ciphers, keyManager, trustManager, and the
// remaining builder methods), and the build() terminal that produces the
// SslContext engine object — including the return types, lifecycle roles,
// and the rules-anchor api FQNs (scanoss/crypto_rules#168) they must resolve
// through.
func TestLoadEmbeddedJava_NettyTLSBuilderLifecycle(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	const builder = "io.netty.handler.ssl.SslContextBuilder"

	tests := []struct {
		method string
		arity  int
		want   string
		role   string
	}{
		// Factories.
		{builder + ".forClient", 0, builder, "factory"},
		{builder + ".forServer", 1, builder, "factory"},
		{builder + ".forServer", 2, builder, "factory"},
		{builder + ".forServer", 3, builder, "factory"},
		// Fluent configuration — every method self-returns SslContextBuilder,
		// which is what lets the chain keep resolving across every call.
		{builder + ".option", 2, builder, "config"},
		{builder + ".sslProvider", 1, builder, "config"},
		{builder + ".keyStoreType", 1, builder, "config"},
		{builder + ".sslContextProvider", 1, builder, "config"},
		{builder + ".trustManager", 1, builder, "config"},
		{builder + ".keyManager", 1, builder, "config"},
		{builder + ".keyManager", 2, builder, "config"},
		{builder + ".keyManager", 3, builder, "config"},
		{builder + ".addCredential", 1, builder, "config"},
		{builder + ".addCredentials", 1, builder, "config"},
		{builder + ".ciphers", 1, builder, "config"},
		{builder + ".ciphers", 2, builder, "config"},
		{builder + ".applicationProtocolConfig", 1, builder, "config"},
		{builder + ".sessionCacheSize", 1, builder, "config"},
		{builder + ".sessionTimeout", 1, builder, "config"},
		{builder + ".clientAuth", 1, builder, "config"},
		{builder + ".protocols", 1, builder, "config"},
		{builder + ".startTls", 1, builder, "config"},
		{builder + ".enableOcsp", 1, builder, "config"},
		{builder + ".secureRandom", 1, builder, "config"},
		{builder + ".endpointIdentificationAlgorithm", 1, builder, "config"},
		{builder + ".serverName", 1, builder, "config"},
		// Terminal: build() executes construction of the SslContext (operation,
		// not factory — forClient/forServer are the builder factories).
		{builder + ".build", 0, "io.netty.handler.ssl.SslContext", "operation"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			c := got[0]
			if c.Return.Type != tt.want || c.Role != tt.role {
				t.Fatalf("%s#%d = %#v, want return %q with role %q", tt.method, tt.arity, c, tt.want, tt.role)
			}
			if c.Return.Confidence != "high" {
				t.Fatalf("%s#%d confidence = %q, want high", tt.method, tt.arity, c.Return.Confidence)
			}
			if c.SourceLibrary != "netty-tls" {
				t.Fatalf("%s#%d source library = %q, want netty-tls", tt.method, tt.arity, c.SourceLibrary)
			}
		})
	}

	// sslProvider's SslProvider argument (index 0) contributes a "provider"
	// metadata role, mirroring the RSAKeyGenerator keySize pattern above.
	sslProvider := kb.ContractsFor(builder+".sslProvider", 1)
	if len(sslProvider) != 1 || len(sslProvider[0].Parameters) != 1 {
		t.Fatalf("sslProvider#1 parameters = %#v, want a single provider parameter role", sslProvider)
	}
	if p := sslProvider[0].Parameters[0]; p.Index == nil || *p.Index != 0 || p.Role != "metadata-contributing" ||
		p.Contributes == nil || p.Contributes.Property != "provider" || p.Contributes.Derivation != "argument_value" {
		t.Fatalf("sslProvider#1 parameters[0] = %#v, want index=0 provider/argument_value", p)
	}

	// protocols' String... argument (index 0) contributes a "protocolVersion"
	// metadata role.
	protocols := kb.ContractsFor(builder+".protocols", 1)
	if len(protocols) != 1 || len(protocols[0].Parameters) != 1 {
		t.Fatalf("protocols#1 parameters = %#v, want a single protocolVersion parameter role", protocols)
	}
	if p := protocols[0].Parameters[0]; p.Index == nil || *p.Index != 0 || p.Role != "metadata-contributing" ||
		p.Contributes == nil || p.Contributes.Property != "protocolVersion" || p.Contributes.Derivation != "argument_value" {
		t.Fatalf("protocols#1 parameters[0] = %#v, want index=0 protocolVersion/argument_value", p)
	}

	for _, typ := range []string{builder, "io.netty.handler.ssl.SslContext"} {
		if len(kb.Hierarchy[typ]) == 0 {
			t.Errorf("hierarchy[%q] is empty", typ)
		}
	}
}

// TestLoadEmbeddedJava_BouncyCastlePkixLifecycle verifies the bcpkix builder
// lifecycle contracts (scanoss/crypto-finder#185): the X509v3CertificateBuilder
// cert-issuance chain (factory constructors, fluent addExtension/
// replaceExtension config, and the build() terminal producing
// X509CertificateHolder), the JcaContentSignerBuilder/BcContentSignerBuilder
// ContentSigner factories the crypto_rules CMS rules anchor on, the
// CMSSignedDataGenerator/CMSEnvelopedDataGenerator generators the
// crypto_rules protocol/cms rules anchor on directly, the SignerInfoGenerator
// builders that feed them, the PKCS#10 certification-request builder, and
// the OCSPReqBuilder request lifecycle -- including return types, lifecycle
// roles, the collapsed-overload arities, and the abstract-builder hierarchy
// edges that let concrete Bc*ContentSignerBuilder/Bc*ContentVerifierProviderBuilder
// subclasses resolve their inherited build() through the shared base.
func TestLoadEmbeddedJava_BouncyCastlePkixLifecycle(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	const (
		x509v3Builder    = "org.bouncycastle.cert.X509v3CertificateBuilder"
		jcaX509v3Builder = "org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder"
		certHolder       = "org.bouncycastle.cert.X509CertificateHolder"
		jcaSignerBuilder = "org.bouncycastle.operator.jcajce.JcaContentSignerBuilder"
		bcSignerBuilder  = "org.bouncycastle.operator.bc.BcContentSignerBuilder"
		bcRSASigner      = "org.bouncycastle.operator.bc.BcRSAContentSignerBuilder"
		contentSigner    = "org.bouncycastle.operator.ContentSigner"
		cmsSignedGen     = "org.bouncycastle.cms.CMSSignedDataGenerator"
		cmsEnvelopedGen  = "org.bouncycastle.cms.CMSEnvelopedDataGenerator"
		signerInfoGen    = "org.bouncycastle.cms.SignerInfoGenerator"
		signerInfoBldr   = "org.bouncycastle.cms.SignerInfoGeneratorBuilder"
		jceEncryptorBldr = "org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder"
		outputEncryptor  = "org.bouncycastle.operator.OutputEncryptor"
		pkcs10Builder    = "org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder"
		pkcs10Req        = "org.bouncycastle.pkcs.PKCS10CertificationRequest"
		ocspReqBuilder   = "org.bouncycastle.cert.ocsp.OCSPReqBuilder"
		ocspReq          = "org.bouncycastle.cert.ocsp.OCSPReq"
	)

	tests := []struct {
		method string
		arity  int
		want   string
		role   string
	}{
		// X509v3CertificateBuilder: factory constructors, fluent config, terminal build.
		{x509v3Builder + ".<init>", 6, x509v3Builder, "factory"},
		{x509v3Builder + ".<init>", 7, x509v3Builder, "factory"},
		{x509v3Builder + ".<init>", 1, x509v3Builder, "factory"},
		{x509v3Builder + ".addExtension", 3, x509v3Builder, "config"},
		{x509v3Builder + ".addExtension", 1, x509v3Builder, "config"},
		{x509v3Builder + ".replaceExtension", 3, x509v3Builder, "config"},
		{x509v3Builder + ".copyAndAddExtension", 3, x509v3Builder, "config"},
		{x509v3Builder + ".build", 1, certHolder, "factory"},
		{x509v3Builder + ".build", 3, certHolder, "factory"},
		// JcaX509v3CertificateBuilder: own constructors + distinct override only.
		{jcaX509v3Builder + ".<init>", 6, jcaX509v3Builder, "factory"},
		{jcaX509v3Builder + ".copyAndAddExtension", 3, jcaX509v3Builder, "config"},
		// ContentSigner factories.
		{jcaSignerBuilder + ".<init>", 1, jcaSignerBuilder, "factory"},
		{jcaSignerBuilder + ".build", 1, contentSigner, "factory"},
		{bcSignerBuilder + ".build", 1, contentSigner, "factory"},
		{bcRSASigner + ".<init>", 2, bcRSASigner, "factory"},
		// CMS generators (the crypto_rules protocol/cms rule anchors).
		{cmsSignedGen + ".<init>", 0, cmsSignedGen, "factory"},
		{cmsSignedGen + ".generate", 1, "org.bouncycastle.cms.CMSSignedData", "operation"},
		{cmsEnvelopedGen + ".<init>", 0, cmsEnvelopedGen, "factory"},
		{cmsEnvelopedGen + ".generate", 2, "org.bouncycastle.cms.CMSEnvelopedData", "operation"},
		// SignerInfoGenerator + content-encryptor builders CMS generators consume.
		{signerInfoBldr + ".<init>", 1, signerInfoBldr, "factory"},
		{signerInfoBldr + ".build", 2, signerInfoGen, "factory"},
		{jceEncryptorBldr + ".<init>", 1, jceEncryptorBldr, "factory"},
		{jceEncryptorBldr + ".build", 0, outputEncryptor, "factory"},
		{jceEncryptorBldr + ".build", 1, outputEncryptor, "factory"},
		// PKCS#10 certification-request builder.
		{pkcs10Builder + ".<init>", 2, pkcs10Builder, "factory"},
		{pkcs10Builder + ".build", 1, pkcs10Req, "factory"},
		// OCSP request builder.
		{ocspReqBuilder + ".<init>", 0, ocspReqBuilder, "factory"},
		{ocspReqBuilder + ".build", 0, ocspReq, "factory"},
		{ocspReqBuilder + ".build", 2, ocspReq, "factory"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			c := got[0]
			if c.Return.Type != tt.want || c.Role != tt.role {
				t.Fatalf("%s#%d = %#v, want return %q with role %q", tt.method, tt.arity, c, tt.want, tt.role)
			}
			if c.Return.Confidence != "high" {
				t.Fatalf("%s#%d confidence = %q, want high", tt.method, tt.arity, c.Return.Confidence)
			}
			if c.SourceLibrary != "bouncycastle-pkix" {
				t.Fatalf("%s#%d source library = %q, want bouncycastle-pkix", tt.method, tt.arity, c.SourceLibrary)
			}
		})
	}

	// Overload-collapsing sanity: JcaX509v3CertificateBuilder.<init>#6
	// collapses FIVE distinct source overloads into a single contract entry
	// (they all return JcaX509v3CertificateBuilder identically).
	if got := kb.ContractsFor(jcaX509v3Builder+".<init>", 6); len(got) != 1 {
		t.Fatalf("%s.<init>#6 contracts = %d, want exactly 1 (collapsed overload)", jcaX509v3Builder, len(got))
	}

	// Abstract-builder hierarchy: BcRSAContentSignerBuilder extends
	// BcContentSignerBuilder, so its inherited build(AsymmetricKeyParameter)
	// resolves through this edge rather than needing a per-subclass contract.
	if parents := kb.Hierarchy[bcRSASigner]; len(parents) != 1 || parents[0] != bcSignerBuilder {
		t.Fatalf("%s hierarchy = %v, want [%s]", bcRSASigner, parents, bcSignerBuilder)
	}

	// JcaX509v3CertificateBuilder/BcX509v3CertificateBuilder both extend the
	// core X509v3CertificateBuilder, so their inherited addExtension/build/etc.
	// resolve through this edge.
	if parents := kb.Hierarchy[jcaX509v3Builder]; len(parents) != 1 || parents[0] != x509v3Builder {
		t.Fatalf("%s hierarchy = %v, want [%s]", jcaX509v3Builder, parents, x509v3Builder)
	}

	for _, typ := range []string{x509v3Builder, certHolder, contentSigner, cmsSignedGen, cmsEnvelopedGen, pkcs10Builder, ocspReqBuilder} {
		if len(kb.Hierarchy[typ]) == 0 {
			t.Errorf("hierarchy[%q] is empty", typ)
		}
	}
}

// TestLoadEmbeddedJava_CommonsCodecBlake3Lifecycle verifies the Commons Codec
// Blake3 stateful/fluent lifecycle contracts (scanoss/crypto-finder#187): the
// three mode-selecting factories (initHash/initKeyedHash/
// initKeyDerivationFunction), the two one-shot statics that inline a full
// factory->update->doFinalize chain (hash/keyedHash), the self-returning
// update (operation/absorb) and doFinalize (operation) steps, and reset —
// including the return types, lifecycle roles, and the rules-anchor api
// FQNs (scanoss/crypto_rules#164, PR #167) they must resolve through.
func TestLoadEmbeddedJava_CommonsCodecBlake3Lifecycle(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	const blake3 = "org.apache.commons.codec.digest.Blake3"

	tests := []struct {
		method string
		arity  int
		want   string
		role   string
	}{
		// Mode-selecting factories -- the three independent Blake3 modes.
		{blake3 + ".initHash", 0, blake3, "factory"},
		{blake3 + ".initKeyedHash", 1, blake3, "factory"},
		{blake3 + ".initKeyDerivationFunction", 1, blake3, "factory"},
		// One-shot statics that inline factory->update->doFinalize.
		{blake3 + ".hash", 1, "byte[]", "factory"},
		{blake3 + ".keyedHash", 2, "byte[]", "factory"},
		// Operation/absorb -- feeds input into the running hash (the digest
		// operation itself); self-returning so the fluent chain keeps resolving.
		{blake3 + ".update", 1, blake3, "operation"},
		{blake3 + ".update", 3, blake3, "operation"},
		// Operation/output -- doFinalize(byte[]...) self-returns too.
		{blake3 + ".doFinalize", 1, blake3, "operation"},
		{blake3 + ".doFinalize", 3, blake3, "operation"},
		// Config -- reset() rewinds engine state, also self-returning.
		{blake3 + ".reset", 0, blake3, "config"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			c := got[0]
			if c.Return.Type != tt.want || c.Role != tt.role {
				t.Fatalf("%s#%d = %#v, want return %q with role %q", tt.method, tt.arity, c, tt.want, tt.role)
			}
			if c.Return.Confidence != "high" {
				t.Fatalf("%s#%d confidence = %q, want high", tt.method, tt.arity, c.Return.Confidence)
			}
			if c.SourceLibrary != "commons-codec-blake3" {
				t.Fatalf("%s#%d source library = %q, want commons-codec-blake3", tt.method, tt.arity, c.SourceLibrary)
			}
		})
	}

	// initKeyedHash's key argument (index 0) contributes a "keySize" metadata
	// role via bit-length derivation, mirroring the RSAKeyGenerator/
	// KeyParameter pattern used elsewhere in this KB.
	initKeyedHash := kb.ContractsFor(blake3+".initKeyedHash", 1)
	if len(initKeyedHash) != 1 || len(initKeyedHash[0].Parameters) != 1 {
		t.Fatalf("initKeyedHash#1 parameters = %#v, want a single keySize parameter role", initKeyedHash)
	}
	if p := initKeyedHash[0].Parameters[0]; p.Index == nil || *p.Index != 0 || p.Role != "metadata-contributing" ||
		p.Contributes == nil || p.Contributes.Property != "keySize" || p.Contributes.Derivation != "argument_bit_length" {
		t.Fatalf("initKeyedHash#1 parameters[0] = %#v, want index=0 keySize/argument_bit_length", p)
	}

	// doFinalize(int nrBytes) is a deliberate arity-collision omission (see
	// the YAML's arity-collision note): only the byte[]-out overload is
	// contracted at arity 1, so the KB must not carry a phantom second entry.
	if got := kb.ContractsFor(blake3+".doFinalize", 1); len(got) != 1 {
		t.Fatalf("doFinalize#1 contracts = %d, want exactly 1 (the byte[]-out overload)", len(got))
	}

	if len(kb.Hierarchy[blake3]) == 0 {
		t.Errorf("hierarchy[%q] is empty", blake3)
	}
}

// TestLoadEmbeddedJava_SpringSecurityCrypto71EncoderLifecycle is the
// scanoss/crypto-finder#182 acceptance test: the version-pinned 7.1 KB
// (spring-security-crypto-7.1.yaml) loads alongside the pre-existing 6.3.4 KB
// (spring-security-crypto.yaml) without conflict, contracts the new
// password4j-backed encoder constructors, the PasswordEncoderFactories
// default DelegatingPasswordEncoder factory, the hand-rolled BCrypt static
// terminal, and the previously-uncontracted AesBytesEncryptor/Encryptors.delux
// surface -- and that the 6.3.4 PasswordEncoder.encode/matches/
// upgradeEncoding contract still resolves for the new password4j encoder
// classes purely through hierarchy (no per-class override is authored).
func TestLoadEmbeddedJava_SpringSecurityCrypto71EncoderLifecycle(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		want   string
		role   string
	}{
		{"org.springframework.security.crypto.bcrypt.BCrypt.hashpw", 2, "java.lang.String", "operation"},
		{"org.springframework.security.crypto.bcrypt.BCrypt.checkpw", 2, "boolean", "operation"},
		{"org.springframework.security.crypto.bcrypt.BCrypt.gensalt", 0, "java.lang.String", "factory"},
		{"org.springframework.security.crypto.bcrypt.BCrypt.gensalt", 1, "java.lang.String", "factory"},
		{"org.springframework.security.crypto.bcrypt.BCrypt.gensalt", 2, "java.lang.String", "factory"},
		{"org.springframework.security.crypto.bcrypt.BCrypt.gensalt", 3, "java.lang.String", "factory"},
		{
			"org.springframework.security.crypto.factory.PasswordEncoderFactories.createDelegatingPasswordEncoder",
			0, "org.springframework.security.crypto.password.DelegatingPasswordEncoder", "factory",
		},
		{"org.springframework.security.crypto.password4j.BcryptPassword4jPasswordEncoder.<init>", 0, "org.springframework.security.crypto.password4j.BcryptPassword4jPasswordEncoder", "factory"},
		{"org.springframework.security.crypto.password4j.BcryptPassword4jPasswordEncoder.<init>", 1, "org.springframework.security.crypto.password4j.BcryptPassword4jPasswordEncoder", "factory"},
		{"org.springframework.security.crypto.password4j.Argon2Password4jPasswordEncoder.<init>", 0, "org.springframework.security.crypto.password4j.Argon2Password4jPasswordEncoder", "factory"},
		{"org.springframework.security.crypto.password4j.ScryptPassword4jPasswordEncoder.<init>", 1, "org.springframework.security.crypto.password4j.ScryptPassword4jPasswordEncoder", "factory"},
		{"org.springframework.security.crypto.password4j.Pbkdf2Password4jPasswordEncoder.<init>", 2, "org.springframework.security.crypto.password4j.Pbkdf2Password4jPasswordEncoder", "factory"},
		{"org.springframework.security.crypto.password4j.BalloonHashingPassword4jPasswordEncoder.<init>", 2, "org.springframework.security.crypto.password4j.BalloonHashingPassword4jPasswordEncoder", "factory"},
		{"org.springframework.security.crypto.encrypt.AesBytesEncryptor.<init>", 2, "org.springframework.security.crypto.encrypt.AesBytesEncryptor", "factory"},
		{"org.springframework.security.crypto.encrypt.AesBytesEncryptor.<init>", 3, "org.springframework.security.crypto.encrypt.AesBytesEncryptor", "factory"},
		{"org.springframework.security.crypto.encrypt.AesBytesEncryptor.<init>", 4, "org.springframework.security.crypto.encrypt.AesBytesEncryptor", "factory"},
		{"org.springframework.security.crypto.encrypt.Encryptors.delux", 2, "org.springframework.security.crypto.encrypt.TextEncryptor", "factory"},
		// Preserved-meaning check: the pre-existing 6.3.4 entries must be
		// untouched by the new 7.1 file (issue AC: "without weakening the
		// existing 6.3.4 contract").
		{"org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.<init>", 0, "org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder", "factory"},
		{"org.springframework.security.crypto.encrypt.Encryptors.standard", 2, "org.springframework.security.crypto.encrypt.BytesEncryptor", "factory"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].Return.Type != tt.want || got[0].Role != tt.role {
				t.Fatalf("%s#%d = %#v, want return %q with role %q", tt.method, tt.arity, got[0], tt.want, tt.role)
			}
		})
	}

	// The new password4j encoder classes must resolve encode/matches purely
	// via hierarchy into the pre-existing 6.3.4 PasswordEncoder contract --
	// no per-class override is authored in spring-security-crypto-7.1.yaml.
	for _, class := range []string{
		"org.springframework.security.crypto.password4j.BcryptPassword4jPasswordEncoder",
		"org.springframework.security.crypto.password4j.Argon2Password4jPasswordEncoder",
		"org.springframework.security.crypto.password4j.ScryptPassword4jPasswordEncoder",
		"org.springframework.security.crypto.password4j.Pbkdf2Password4jPasswordEncoder",
		"org.springframework.security.crypto.password4j.BalloonHashingPassword4jPasswordEncoder",
	} {
		parents := kb.Hierarchy[class]
		if len(parents) != 1 || parents[0] != "org.springframework.security.crypto.password.PasswordEncoder" {
			t.Errorf("%s hierarchy = %v, want [PasswordEncoder]", class, parents)
		}
		if encode := kb.ContractsFor(class+".encode", 1); len(encode) != 0 {
			t.Errorf("%s.encode#1 should not be directly contracted (resolves via PasswordEncoder hierarchy), got %#v", class, encode)
		}
	}

	if parents := kb.Hierarchy["org.springframework.security.crypto.encrypt.AesBytesEncryptor"]; len(parents) != 1 || parents[0] != "org.springframework.security.crypto.encrypt.BytesEncryptor" {
		t.Fatalf("AesBytesEncryptor hierarchy = %v, want [BytesEncryptor]", parents)
	}
	if parents := kb.Hierarchy["org.springframework.security.crypto.password.DelegatingPasswordEncoder"]; len(parents) != 1 || parents[0] != "org.springframework.security.crypto.password.PasswordEncoder" {
		t.Fatalf("DelegatingPasswordEncoder hierarchy = %v, want [PasswordEncoder]", parents)
	}
}

// TestLoadEmbeddedJava_JavaJwtAndJwksRsaLifecycle verifies the Auth0 java-jwt
// and jwks-rsa contracts (scanoss/crypto-finder#203): the JWT.create fluent
// signing chain, the JWT.require verification chain built on the Verification
// interface, the Algorithm factories, and the JWKS key-resolution surface
// (JwkProviderBuilder fluent chain, JwkProvider.get, Jwk.getPublicKey) —
// including return types, lifecycle roles, and the hierarchy edges that let
// concrete providers and BaseVerification resolve to their interface
// declarations.
func TestLoadEmbeddedJava_JavaJwtAndJwksRsaLifecycle(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		want   string
		role   string
		lib    string
	}{
		// java-jwt: creation + signing chain.
		{"com.auth0.jwt.JWT.create", 0, "com.auth0.jwt.JWTCreator.Builder", "factory", "java-jwt"},
		{"com.auth0.jwt.JWTCreator.Builder.withIssuer", 1, "com.auth0.jwt.JWTCreator.Builder", "config", "java-jwt"},
		{"com.auth0.jwt.JWTCreator.Builder.withClaim", 2, "com.auth0.jwt.JWTCreator.Builder", "config", "java-jwt"},
		{"com.auth0.jwt.JWTCreator.Builder.sign", 1, "java.lang.String", "operation", "java-jwt"},
		// java-jwt: algorithm factories (HMAC/RSA/ECDSA/PSS/none).
		{"com.auth0.jwt.algorithms.Algorithm.HMAC256", 1, "com.auth0.jwt.algorithms.Algorithm", "factory", "java-jwt"},
		{"com.auth0.jwt.algorithms.Algorithm.RSA256", 2, "com.auth0.jwt.algorithms.Algorithm", "factory", "java-jwt"},
		{"com.auth0.jwt.algorithms.Algorithm.RSA512PSS", 2, "com.auth0.jwt.algorithms.Algorithm", "factory", "java-jwt"},
		{"com.auth0.jwt.algorithms.Algorithm.ECDSA256", 1, "com.auth0.jwt.algorithms.Algorithm", "factory", "java-jwt"},
		{"com.auth0.jwt.algorithms.Algorithm.none", 0, "com.auth0.jwt.algorithms.Algorithm", "factory", "java-jwt"},
		// java-jwt: raw sign/verify operations on the Algorithm base.
		{"com.auth0.jwt.algorithms.Algorithm.sign", 2, "byte[]", "operation", "java-jwt"},
		{"com.auth0.jwt.algorithms.Algorithm.verify", 1, "void", "operation", "java-jwt"},
		// java-jwt: verification chain (Verification interface -> JWTVerifier).
		{"com.auth0.jwt.JWT.require", 1, "com.auth0.jwt.interfaces.Verification", "factory", "java-jwt"},
		{"com.auth0.jwt.interfaces.Verification.withIssuer", 1, "com.auth0.jwt.interfaces.Verification", "config", "java-jwt"},
		{"com.auth0.jwt.interfaces.Verification.acceptLeeway", 1, "com.auth0.jwt.interfaces.Verification", "config", "java-jwt"},
		{"com.auth0.jwt.interfaces.Verification.build", 0, "com.auth0.jwt.JWTVerifier", "factory", "java-jwt"},
		{"com.auth0.jwt.interfaces.JWTVerifier.verify", 1, "com.auth0.jwt.interfaces.DecodedJWT", "operation", "java-jwt"},
		{"com.auth0.jwt.JWT.decode", 1, "com.auth0.jwt.interfaces.DecodedJWT", "factory", "java-jwt"},
		// jwks-rsa: provider construction + key resolution.
		{"com.auth0.jwk.JwkProviderBuilder.<init>", 1, "com.auth0.jwk.JwkProviderBuilder", "factory", "jwks-rsa"},
		{"com.auth0.jwk.JwkProviderBuilder.cached", 3, "com.auth0.jwk.JwkProviderBuilder", "config", "jwks-rsa"},
		{"com.auth0.jwk.JwkProviderBuilder.rateLimited", 3, "com.auth0.jwk.JwkProviderBuilder", "config", "jwks-rsa"},
		{"com.auth0.jwk.JwkProviderBuilder.build", 0, "com.auth0.jwk.JwkProvider", "factory", "jwks-rsa"},
		{"com.auth0.jwk.JwkProvider.get", 1, "com.auth0.jwk.Jwk", "factory", "jwks-rsa"},
		{"com.auth0.jwk.UrlJwkProvider.<init>", 1, "com.auth0.jwk.UrlJwkProvider", "factory", "jwks-rsa"},
		{"com.auth0.jwk.Jwk.fromValues", 1, "com.auth0.jwk.Jwk", "factory", "jwks-rsa"},
		{"com.auth0.jwk.Jwk.getPublicKey", 0, "java.security.PublicKey", "output", "jwks-rsa"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].Return.Type != tt.want || got[0].Role != tt.role || got[0].SourceLibrary != tt.lib {
				t.Fatalf("%s#%d = %#v, want return %q with role %q from %q", tt.method, tt.arity, got[0], tt.want, tt.role, tt.lib)
			}
		})
	}

	// The HMAC factories take the key material directly; the secret argument
	// contributes the key size by bit length, mirroring the byte[]-key factory
	// convention in the bouncycastle-openpgp and go KBs.
	hmac := kb.ContractsFor("com.auth0.jwt.algorithms.Algorithm.HMAC256", 1)
	if len(hmac) != 1 || len(hmac[0].Parameters) != 1 {
		t.Fatalf("Algorithm.HMAC256#1 parameters = %#v, want one secret parameter role", hmac)
	}
	p := hmac[0].Parameters[0]
	if p.Index == nil || *p.Index != 0 || p.Role != "metadata-contributing" || p.Contributes == nil || p.Contributes.Property != "keySize" || p.Contributes.Derivation != "argument_bit_length" {
		t.Fatalf("Algorithm.HMAC256#1 parameters[0] = %#v, want index=0 keySize/argument_bit_length", p)
	}

	// BaseVerification implements Verification; the concrete verifier and the
	// concrete JWKS providers must resolve to their interface declarations.
	if parents := kb.Hierarchy["com.auth0.jwt.JWTVerifier.BaseVerification"]; len(parents) != 1 || parents[0] != "com.auth0.jwt.interfaces.Verification" {
		t.Fatalf("BaseVerification hierarchy = %v, want [Verification]", parents)
	}
	if parents := kb.Hierarchy["com.auth0.jwt.JWTVerifier"]; len(parents) != 1 || parents[0] != "com.auth0.jwt.interfaces.JWTVerifier" {
		t.Fatalf("JWTVerifier hierarchy = %v, want [interfaces.JWTVerifier]", parents)
	}
	for _, provider := range []string{
		"com.auth0.jwk.UrlJwkProvider",
		"com.auth0.jwk.GuavaCachedJwkProvider",
		"com.auth0.jwk.RateLimitedJwkProvider",
	} {
		if parents := kb.Hierarchy[provider]; len(parents) != 1 || parents[0] != "com.auth0.jwk.JwkProvider" {
			t.Fatalf("%s hierarchy = %v, want [JwkProvider]", provider, parents)
		}
	}
}

// TestLoadEmbeddedJava_HutoolEddsaPgpainlessLifecycle verifies the Tier 0
// RULE_ONLY gap contracts (scanoss/crypto-finder#207): hutool-crypto's
// SecureUtil/DigestUtil/SmUtil/KeyUtil factories and symmetric/digest/MAC/
// asymmetric lifecycles, i2p-eddsa's signing engine and key/spec construction,
// and pgpainless's encrypt/decrypt/keygen fluent chains — including the
// rule-anchor methods, return types, lifecycle roles, and the hierarchy edges
// that resolve subclasses and chain interfaces.
func TestLoadEmbeddedJava_HutoolEddsaPgpainlessLifecycle(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		want   string
		role   string
		lib    string
	}{
		// hutool-crypto: rule anchors (SecureUtil.aes/des/desede/rsa/md5/sha*).
		{"cn.hutool.crypto.SecureUtil.aes", 1, "cn.hutool.crypto.symmetric.AES", "factory", "hutool-crypto"},
		{"cn.hutool.crypto.SecureUtil.des", 0, "cn.hutool.crypto.symmetric.DES", "factory", "hutool-crypto"},
		{"cn.hutool.crypto.SecureUtil.desede", 1, "cn.hutool.crypto.symmetric.DESede", "factory", "hutool-crypto"},
		{"cn.hutool.crypto.SecureUtil.rsa", 0, "cn.hutool.crypto.asymmetric.RSA", "factory", "hutool-crypto"},
		// The md5/sha1 arity split: 0 -> digester object, 1 -> hex string.
		{"cn.hutool.crypto.SecureUtil.md5", 0, "cn.hutool.crypto.digest.MD5", "factory", "hutool-crypto"},
		{"cn.hutool.crypto.SecureUtil.md5", 1, "java.lang.String", "operation", "hutool-crypto"},
		{"cn.hutool.crypto.SecureUtil.hmacSha256", 1, "cn.hutool.crypto.digest.HMac", "factory", "hutool-crypto"},
		{"cn.hutool.crypto.digest.DigestUtil.sha256Hex", 1, "java.lang.String", "operation", "hutool-crypto"},
		{"cn.hutool.crypto.SmUtil.sm2", 0, "cn.hutool.crypto.asymmetric.SM2", "factory", "hutool-crypto"},
		{"cn.hutool.crypto.SmUtil.sm4", 1, "cn.hutool.crypto.symmetric.SM4", "factory", "hutool-crypto"},
		{"cn.hutool.crypto.KeyUtil.generateKeyPair", 2, "java.security.KeyPair", "factory", "hutool-crypto"},
		// hutool lifecycle on base classes (subclasses resolve via hierarchy).
		{"cn.hutool.crypto.symmetric.SymmetricCrypto.encrypt", 1, "byte[]", "operation", "hutool-crypto"},
		{"cn.hutool.crypto.symmetric.SymmetricCrypto.setIv", 1, "cn.hutool.crypto.symmetric.SymmetricCrypto", "config", "hutool-crypto"},
		{"cn.hutool.crypto.digest.Digester.digestHex", 1, "java.lang.String", "operation", "hutool-crypto"},
		{"cn.hutool.crypto.digest.mac.Mac.digest", 1, "byte[]", "operation", "hutool-crypto"},
		{"cn.hutool.crypto.asymmetric.AsymmetricCrypto.encrypt", 2, "byte[]", "operation", "hutool-crypto"},
		{"cn.hutool.crypto.asymmetric.Sign.sign", 1, "byte[]", "operation", "hutool-crypto"},
		{"cn.hutool.crypto.asymmetric.SM2.verify", 2, "boolean", "operation", "hutool-crypto"},
		// i2p-eddsa: rule anchors (new EdDSAEngine, EdDSANamedCurveTable.getByName).
		{"net.i2p.crypto.eddsa.EdDSAEngine.<init>", 0, "net.i2p.crypto.eddsa.EdDSAEngine", "factory", "i2p-eddsa"},
		{"net.i2p.crypto.eddsa.EdDSAEngine.<init>", 1, "net.i2p.crypto.eddsa.EdDSAEngine", "factory", "i2p-eddsa"},
		{"net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable.getByName", 1, "net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec", "factory", "i2p-eddsa"},
		{"net.i2p.crypto.eddsa.EdDSAEngine.signOneShot", 1, "byte[]", "operation", "i2p-eddsa"},
		{"net.i2p.crypto.eddsa.EdDSAEngine.verifyOneShot", 2, "boolean", "operation", "i2p-eddsa"},
		{"net.i2p.crypto.eddsa.KeyPairGenerator.generateKeyPair", 0, "java.security.KeyPair", "factory", "i2p-eddsa"},
		{"net.i2p.crypto.eddsa.EdDSAPrivateKey.<init>", 1, "net.i2p.crypto.eddsa.EdDSAPrivateKey", "factory", "i2p-eddsa"},
		// pgpainless: rule anchors and the fluent chains.
		{"org.pgpainless.PGPainless.encryptAndOrSign", 0, "org.pgpainless.encryption_signing.EncryptionBuilder", "factory", "pgpainless"},
		{"org.pgpainless.PGPainless.decryptAndOrVerify", 0, "org.pgpainless.decryption_verification.DecryptionBuilder", "factory", "pgpainless"},
		{"org.pgpainless.PGPainless.generateKeyRing", 0, "org.pgpainless.key.generation.KeyRingTemplates", "factory", "pgpainless"},
		{"org.pgpainless.encryption_signing.EncryptionBuilder.onOutputStream", 1, "org.pgpainless.encryption_signing.EncryptionBuilderInterface.WithOptions", "config", "pgpainless"},
		{"org.pgpainless.encryption_signing.EncryptionBuilderInterface.WithOptions.withOptions", 1, "org.pgpainless.encryption_signing.EncryptionStream", "factory", "pgpainless"},
		{"org.pgpainless.encryption_signing.EncryptionStream.getResult", 0, "org.pgpainless.encryption_signing.EncryptionResult", "output", "pgpainless"},
		{"org.pgpainless.encryption_signing.ProducerOptions.signAndEncrypt", 2, "org.pgpainless.encryption_signing.ProducerOptions", "factory", "pgpainless"},
		{"org.pgpainless.encryption_signing.EncryptionOptions.addRecipient", 1, "org.pgpainless.encryption_signing.EncryptionOptions", "config", "pgpainless"},
		{"org.pgpainless.encryption_signing.SigningOptions.addInlineSignature", 3, "org.pgpainless.encryption_signing.SigningOptions", "config", "pgpainless"},
		{"org.pgpainless.decryption_verification.DecryptionBuilderInterface.DecryptWith.withOptions", 1, "org.pgpainless.decryption_verification.DecryptionStream", "factory", "pgpainless"},
		{"org.pgpainless.decryption_verification.ConsumerOptions.addDecryptionKey", 1, "org.pgpainless.decryption_verification.ConsumerOptions", "config", "pgpainless"},
		{"org.pgpainless.decryption_verification.DecryptionStream.getMetadata", 0, "org.pgpainless.decryption_verification.MessageMetadata", "output", "pgpainless"},
		{"org.pgpainless.key.generation.KeyRingTemplates.modernKeyRing", 1, "org.bouncycastle.openpgp.PGPSecretKeyRing", "factory", "pgpainless"},
		{"org.pgpainless.key.generation.KeyRingBuilder.build", 0, "org.bouncycastle.openpgp.PGPSecretKeyRing", "factory", "pgpainless"},
		{"org.pgpainless.key.parsing.KeyRingReader.secretKeyRing", 1, "org.bouncycastle.openpgp.PGPSecretKeyRing", "factory", "pgpainless"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].Return.Type != tt.want || got[0].Role != tt.role || got[0].SourceLibrary != tt.lib {
				t.Fatalf("%s#%d = %#v, want return %q with role %q from %q", tt.method, tt.arity, got[0], tt.want, tt.role, tt.lib)
			}
		})
	}

	// Subclasses and chain implementations must resolve to the base/interface
	// declarations the lifecycle contracts are authored on.
	hierarchyWants := map[string]string{
		"cn.hutool.crypto.symmetric.AES":                                      "cn.hutool.crypto.symmetric.SymmetricCrypto",
		"cn.hutool.crypto.symmetric.SM4":                                      "cn.hutool.crypto.symmetric.SymmetricCrypto",
		"cn.hutool.crypto.digest.MD5":                                         "cn.hutool.crypto.digest.Digester",
		"cn.hutool.crypto.digest.HMac":                                        "cn.hutool.crypto.digest.mac.Mac",
		"cn.hutool.crypto.asymmetric.RSA":                                     "cn.hutool.crypto.asymmetric.AsymmetricCrypto",
		"net.i2p.crypto.eddsa.EdDSAEngine":                                    "java.security.Signature",
		"org.pgpainless.encryption_signing.EncryptionBuilder.WithOptionsImpl": "org.pgpainless.encryption_signing.EncryptionBuilderInterface.WithOptions",
		"org.pgpainless.decryption_verification.OpenPgpMessageInputStream":    "org.pgpainless.decryption_verification.DecryptionStream",
	}
	for child, wantParent := range hierarchyWants {
		if parents := kb.Hierarchy[child]; len(parents) == 0 || parents[0] != wantParent {
			t.Fatalf("%s hierarchy = %v, want first parent %s", child, kb.Hierarchy[child], wantParent)
		}
	}

	// The AES key-material constructor contributes keySize by bit length.
	aes := kb.ContractsFor("cn.hutool.crypto.symmetric.AES.<init>", 1)
	if len(aes) != 1 || len(aes[0].Parameters) != 1 {
		t.Fatalf("AES.<init>#1 parameters = %#v, want one key parameter role", aes)
	}
	p := aes[0].Parameters[0]
	if p.Index == nil || *p.Index != 0 || p.Role != "metadata-contributing" || p.Contributes == nil || p.Contributes.Property != "keySize" || p.Contributes.Derivation != "argument_bit_length" {
		t.Fatalf("AES.<init>#1 parameters[0] = %#v, want index=0 keySize/argument_bit_length", p)
	}
}

// TestLoadEmbeddedJava_PasswordHasherLifecycle verifies the Java password/KDF
// facade contracts (scanoss/crypto-finder#202): jbcrypt, favre-bcrypt,
// lambdaworks-scrypt, argon2-jvm, and jasypt. It pins the rule-anchor methods,
// the hash/verify entry points and their return types, the lifecycle roles, and
// the cost/iteration parameter roles that carry the KDF work factors.
func TestLoadEmbeddedJava_PasswordHasherLifecycle(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		want   string
		role   string
		lib    string
	}{
		// jbcrypt — the FQN is the one shipped in the org.mindrot:jbcrypt jar.
		{"org.mindrot.jbcrypt.BCrypt.hashpw", 2, "java.lang.String", "operation", "jbcrypt"},
		{"org.mindrot.jbcrypt.BCrypt.checkpw", 2, "boolean", "operation", "jbcrypt"},
		{"org.mindrot.jbcrypt.BCrypt.gensalt", 0, "java.lang.String", "factory", "jbcrypt"},
		{"org.mindrot.jbcrypt.BCrypt.gensalt", 1, "java.lang.String", "factory", "jbcrypt"},
		// favre-bcrypt — fluent hasher/verifyer; verify returns Result, not boolean.
		{"at.favre.lib.crypto.bcrypt.BCrypt.withDefaults", 0, "at.favre.lib.crypto.bcrypt.BCrypt.Hasher", "factory", "favre-bcrypt"},
		{"at.favre.lib.crypto.bcrypt.BCrypt.with", 1, "at.favre.lib.crypto.bcrypt.BCrypt.Hasher", "factory", "favre-bcrypt"},
		{"at.favre.lib.crypto.bcrypt.BCrypt.verifyer", 0, "at.favre.lib.crypto.bcrypt.BCrypt.Verifyer", "factory", "favre-bcrypt"},
		{"at.favre.lib.crypto.bcrypt.BCrypt.Hasher.hashToString", 2, "java.lang.String", "operation", "favre-bcrypt"},
		{"at.favre.lib.crypto.bcrypt.BCrypt.Hasher.hashToChar", 2, "char[]", "operation", "favre-bcrypt"},
		{"at.favre.lib.crypto.bcrypt.BCrypt.Hasher.hash", 2, "byte[]", "operation", "favre-bcrypt"},
		{"at.favre.lib.crypto.bcrypt.BCrypt.Verifyer.verify", 2, "at.favre.lib.crypto.bcrypt.BCrypt.Result", "operation", "favre-bcrypt"},
		{"at.favre.lib.crypto.bcrypt.BCrypt.Verifyer.verifyStrict", 2, "at.favre.lib.crypto.bcrypt.BCrypt.Result", "operation", "favre-bcrypt"},
		{"at.favre.lib.crypto.bcrypt.LongPasswordStrategies.hashSha512", 1, "at.favre.lib.crypto.bcrypt.LongPasswordStrategy", "factory", "favre-bcrypt"},
		// lambdaworks-scrypt — KDF core plus the MCF password facade.
		{"com.lambdaworks.crypto.SCrypt.scrypt", 6, "byte[]", "operation", "lambdaworks-scrypt"},
		{"com.lambdaworks.crypto.SCrypt.scryptJ", 6, "byte[]", "operation", "lambdaworks-scrypt"},
		{"com.lambdaworks.crypto.SCryptUtil.scrypt", 4, "java.lang.String", "operation", "lambdaworks-scrypt"},
		{"com.lambdaworks.crypto.SCryptUtil.check", 2, "boolean", "operation", "lambdaworks-scrypt"},
		// argon2-jvm — create vs createAdvanced differ only by declared return.
		{"de.mkammerer.argon2.Argon2Factory.create", 0, "de.mkammerer.argon2.Argon2", "factory", "argon2-jvm"},
		{"de.mkammerer.argon2.Argon2Factory.create", 1, "de.mkammerer.argon2.Argon2", "factory", "argon2-jvm"},
		{"de.mkammerer.argon2.Argon2Factory.createAdvanced", 0, "de.mkammerer.argon2.Argon2Advanced", "factory", "argon2-jvm"},
		{"de.mkammerer.argon2.Argon2.hash", 4, "java.lang.String", "operation", "argon2-jvm"},
		{"de.mkammerer.argon2.Argon2.verify", 2, "boolean", "operation", "argon2-jvm"},
		{"de.mkammerer.argon2.Argon2Advanced.rawHash", 5, "byte[]", "operation", "argon2-jvm"},
		{"de.mkammerer.argon2.Argon2Advanced.generateSalt", 0, "byte[]", "factory", "argon2-jvm"},
		// jasypt — util facades, PBE engines, and standard digesters.
		{"org.jasypt.util.password.StrongPasswordEncryptor.<init>", 0, "org.jasypt.util.password.StrongPasswordEncryptor", "factory", "jasypt"},
		{"org.jasypt.util.password.PasswordEncryptor.encryptPassword", 1, "java.lang.String", "operation", "jasypt"},
		{"org.jasypt.util.password.PasswordEncryptor.checkPassword", 2, "boolean", "operation", "jasypt"},
		{"org.jasypt.util.text.BasicTextEncryptor.<init>", 0, "org.jasypt.util.text.BasicTextEncryptor", "factory", "jasypt"},
		{"org.jasypt.util.text.TextEncryptor.encrypt", 1, "java.lang.String", "operation", "jasypt"},
		{"org.jasypt.util.binary.BinaryEncryptor.encrypt", 1, "byte[]", "operation", "jasypt"},
		{"org.jasypt.encryption.pbe.StandardPBEStringEncryptor.<init>", 0, "org.jasypt.encryption.pbe.StandardPBEStringEncryptor", "factory", "jasypt"},
		{"org.jasypt.encryption.pbe.StandardPBEStringEncryptor.encrypt", 1, "java.lang.String", "operation", "jasypt"},
		{"org.jasypt.encryption.pbe.StandardPBEByteEncryptor.encrypt", 1, "byte[]", "operation", "jasypt"},
		{"org.jasypt.digest.StandardStringDigester.digest", 1, "java.lang.String", "operation", "jasypt"},
		{"org.jasypt.digest.StandardByteDigester.digest", 1, "byte[]", "operation", "jasypt"},
		{"org.jasypt.util.digest.Digester.digest", 1, "byte[]", "operation", "jasypt"},
		{"org.jasypt.salt.RandomSaltGenerator.<init>", 0, "org.jasypt.salt.RandomSaltGenerator", "factory", "jasypt"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].Return.Type != tt.want || got[0].Role != tt.role || got[0].SourceLibrary != tt.lib {
				t.Fatalf("%s#%d = %#v, want return %q with role %q from %q", tt.method, tt.arity, got[0], tt.want, tt.role, tt.lib)
			}
		})
	}

	// Work-factor parameter roles: bcrypt cost, scrypt N/r/p, and the jasypt PBE
	// key-obtention iteration count must all reach the consumer.
	workFactors := []struct {
		method     string
		arity      int
		index      int
		property   string
		derivation string
	}{
		{"org.mindrot.jbcrypt.BCrypt.gensalt", 1, 0, "cost", "argument_value"},
		{"at.favre.lib.crypto.bcrypt.BCrypt.Hasher.hashToString", 2, 0, "cost", "argument_value"},
		{"com.lambdaworks.crypto.SCryptUtil.scrypt", 4, 1, "cost", "argument_value"},
		{"de.mkammerer.argon2.Argon2.hash", 4, 0, "iterations", "argument_value"},
		{"org.jasypt.encryption.pbe.StandardPBEStringEncryptor.setKeyObtentionIterations", 1, 0, "iterations", "argument_value"},
		{"org.jasypt.digest.StandardStringDigester.setIterations", 1, 0, "iterations", "argument_value"},
	}
	for _, wf := range workFactors {
		got := kb.ContractsFor(wf.method, wf.arity)
		if len(got) != 1 || len(got[0].Parameters) == 0 {
			t.Fatalf("%s#%d parameters = %#v, want at least one parameter role", wf.method, wf.arity, got)
		}
		var found bool
		for _, p := range got[0].Parameters {
			if p.Index == nil || *p.Index != wf.index {
				continue
			}
			found = true
			if p.Role != "metadata-contributing" || p.Contributes == nil ||
				p.Contributes.Property != wf.property || p.Contributes.Derivation != wf.derivation {
				t.Fatalf("%s#%d parameters[%d] = %#v, want %s/%s", wf.method, wf.arity, wf.index, p, wf.property, wf.derivation)
			}
		}
		if !found {
			t.Fatalf("%s#%d has no parameter role at index %d", wf.method, wf.arity, wf.index)
		}
	}

	// Concrete facades must resolve to the interfaces the operations are
	// authored on, and Argon2Advanced must extend Argon2.
	hierarchyWants := map[string]string{
		"org.jasypt.util.password.StrongPasswordEncryptor": "org.jasypt.util.password.PasswordEncryptor",
		"org.jasypt.util.text.BasicTextEncryptor":          "org.jasypt.util.text.TextEncryptor",
		"org.jasypt.util.binary.BasicBinaryEncryptor":      "org.jasypt.util.binary.BinaryEncryptor",
		"de.mkammerer.argon2.Argon2Advanced":               "de.mkammerer.argon2.Argon2",
	}
	for child, wantParent := range hierarchyWants {
		if parents := kb.Hierarchy[child]; len(parents) == 0 || parents[0] != wantParent {
			t.Fatalf("%s hierarchy = %v, want first parent %s", child, kb.Hierarchy[child], wantParent)
		}
	}
}

// TestLoadEmbeddedJava_NaClBindingLifecycle verifies the Java libsodium/NaCl
// binding contracts (scanoss/crypto-finder#205): lazysodium-java's rule-anchored
// AEAD/Box/GenericHash/PwHash/SecretBox/Sign interface pairs plus key material,
// and kalium's Box/SecretBox/SealedBox/Aead/Hash/Password/key surfaces. It pins
// the Lazy-vs-Native split (high-level object returns vs boolean buffer forms),
// the algorithm-bearing native AEAD entry points, and the work-factor and key
// parameter roles.
func TestLoadEmbeddedJava_NaClBindingLifecycle(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		want   string
		role   string
		lib    string
	}{
		// lazysodium: facade construction and key material.
		{"com.goterl.lazysodium.LazySodiumJava.<init>", 1, "com.goterl.lazysodium.LazySodiumJava", "factory", "lazysodium"},
		{"com.goterl.lazysodium.SodiumJava.<init>", 0, "com.goterl.lazysodium.SodiumJava", "factory", "lazysodium"},
		{"com.goterl.lazysodium.utils.Key.fromBytes", 1, "com.goterl.lazysodium.utils.Key", "factory", "lazysodium"},
		{"com.goterl.lazysodium.utils.Key.generate", 2, "com.goterl.lazysodium.utils.Key", "factory", "lazysodium"},
		{"com.goterl.lazysodium.utils.KeyPair.getSecretKey", 0, "com.goterl.lazysodium.utils.Key", "output", "lazysodium"},
		// lazysodium Lazy forms return high-level objects.
		{"com.goterl.lazysodium.interfaces.SecretBox.Lazy.cryptoSecretBoxKeygen", 0, "com.goterl.lazysodium.utils.Key", "factory", "lazysodium"},
		{"com.goterl.lazysodium.interfaces.SecretBox.Lazy.cryptoSecretBoxEasy", 3, "java.lang.String", "operation", "lazysodium"},
		{"com.goterl.lazysodium.interfaces.SecretBox.Lazy.cryptoSecretBoxDetached", 3, "com.goterl.lazysodium.utils.DetachedEncrypt", "operation", "lazysodium"},
		{"com.goterl.lazysodium.interfaces.Box.Lazy.cryptoBoxKeypair", 0, "com.goterl.lazysodium.utils.KeyPair", "factory", "lazysodium"},
		{"com.goterl.lazysodium.interfaces.Box.Lazy.cryptoBoxEasy", 3, "java.lang.String", "operation", "lazysodium"},
		{"com.goterl.lazysodium.interfaces.Box.Lazy.cryptoBoxSealEasy", 2, "java.lang.String", "operation", "lazysodium"},
		{"com.goterl.lazysodium.interfaces.GenericHash.Lazy.cryptoGenericHash", 2, "java.lang.String", "operation", "lazysodium"},
		{"com.goterl.lazysodium.interfaces.PwHash.Lazy.cryptoPwHashStr", 3, "java.lang.String", "operation", "lazysodium"},
		{"com.goterl.lazysodium.interfaces.PwHash.Lazy.cryptoPwHashStrVerify", 2, "boolean", "operation", "lazysodium"},
		{"com.goterl.lazysodium.interfaces.Sign.Lazy.cryptoSignKeypair", 0, "com.goterl.lazysodium.utils.KeyPair", "factory", "lazysodium"},
		{"com.goterl.lazysodium.interfaces.Sign.Lazy.cryptoSignDetached", 2, "java.lang.String", "operation", "lazysodium"},
		{"com.goterl.lazysodium.interfaces.Sign.Lazy.cryptoSignVerifyDetached", 3, "boolean", "operation", "lazysodium"},
		{"com.goterl.lazysodium.interfaces.AEAD.Lazy.keygen", 1, "com.goterl.lazysodium.utils.Key", "factory", "lazysodium"},
		{"com.goterl.lazysodium.interfaces.AEAD.Lazy.encrypt", 5, "java.lang.String", "operation", "lazysodium"},
		// lazysodium Native forms are buffer-based and boolean/void-returning;
		// the AEAD names carry the algorithm family.
		{"com.goterl.lazysodium.interfaces.SecretBox.Native.cryptoSecretBoxEasy", 5, "boolean", "operation", "lazysodium"},
		{"com.goterl.lazysodium.interfaces.AEAD.Native.cryptoAeadXChaCha20Poly1305IetfEncrypt", 9, "boolean", "operation", "lazysodium"},
		{"com.goterl.lazysodium.interfaces.AEAD.Native.cryptoAeadAES256GCMEncrypt", 9, "boolean", "operation", "lazysodium"},
		{"com.goterl.lazysodium.interfaces.AEAD.Native.cryptoAeadAES256GCMKeygen", 1, "void", "factory", "lazysodium"},
		// kalium: rule anchors are the Box/Hash/SecretBox constructors.
		{"org.abstractj.kalium.crypto.Box.<init>", 2, "org.abstractj.kalium.crypto.Box", "factory", "kalium"},
		{"org.abstractj.kalium.crypto.SecretBox.<init>", 1, "org.abstractj.kalium.crypto.SecretBox", "factory", "kalium"},
		{"org.abstractj.kalium.crypto.Hash.<init>", 0, "org.abstractj.kalium.crypto.Hash", "factory", "kalium"},
		{"org.abstractj.kalium.crypto.Box.encrypt", 2, "byte[]", "operation", "kalium"},
		{"org.abstractj.kalium.crypto.SecretBox.decrypt", 2, "byte[]", "operation", "kalium"},
		{"org.abstractj.kalium.crypto.SealedBox.encrypt", 1, "byte[]", "operation", "kalium"},
		{"org.abstractj.kalium.crypto.Aead.useAesGcm", 0, "org.abstractj.kalium.crypto.Aead", "config", "kalium"},
		{"org.abstractj.kalium.crypto.Aead.encrypt", 3, "byte[]", "operation", "kalium"},
		// kalium Hash splits byte[] (arity 1) from String (arity 2 with encoder).
		{"org.abstractj.kalium.crypto.Hash.sha256", 1, "byte[]", "operation", "kalium"},
		{"org.abstractj.kalium.crypto.Hash.sha256", 2, "java.lang.String", "operation", "kalium"},
		{"org.abstractj.kalium.crypto.Password.hash", 4, "java.lang.String", "operation", "kalium"},
		{"org.abstractj.kalium.crypto.Password.verify", 2, "boolean", "operation", "kalium"},
		{"org.abstractj.kalium.keys.SigningKey.sign", 1, "byte[]", "operation", "kalium"},
		{"org.abstractj.kalium.keys.VerifyKey.verify", 2, "boolean", "operation", "kalium"},
		{"org.abstractj.kalium.keys.KeyPair.getPrivateKey", 0, "org.abstractj.kalium.keys.PrivateKey", "output", "kalium"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].Return.Type != tt.want || got[0].Role != tt.role || got[0].SourceLibrary != tt.lib {
				t.Fatalf("%s#%d = %#v, want return %q with role %q from %q", tt.method, tt.arity, got[0], tt.want, tt.role, tt.lib)
			}
		})
	}

	// cryptoGenericHashKeygen is the one lazysodium name where the Lazy and
	// Native forms share arity 1: Lazy(int) -> Key vs Native(byte[]) -> void.
	// They must stay distinct contracts keyed by the declaring interface.
	lazyKeygen := kb.ContractsFor("com.goterl.lazysodium.interfaces.GenericHash.Lazy.cryptoGenericHashKeygen", 1)
	nativeKeygen := kb.ContractsFor("com.goterl.lazysodium.interfaces.GenericHash.Native.cryptoGenericHashKeygen", 1)
	if len(lazyKeygen) != 1 || lazyKeygen[0].Return.Type != "com.goterl.lazysodium.utils.Key" {
		t.Fatalf("GenericHash.Lazy.cryptoGenericHashKeygen#1 = %#v, want Key", lazyKeygen)
	}
	if len(nativeKeygen) != 1 || nativeKeygen[0].Return.Type != "void" {
		t.Fatalf("GenericHash.Native.cryptoGenericHashKeygen#1 = %#v, want void", nativeKeygen)
	}

	// The AEAD.Lazy methods take the algorithm as a trailing enum argument, so
	// that parameter must be operation-determining rather than metadata.
	aeadEncrypt := kb.ContractsFor("com.goterl.lazysodium.interfaces.AEAD.Lazy.encrypt", 5)
	if len(aeadEncrypt) != 1 || len(aeadEncrypt[0].Parameters) != 1 {
		t.Fatalf("AEAD.Lazy.encrypt#5 parameters = %#v, want the trailing method parameter", aeadEncrypt)
	}
	p := aeadEncrypt[0].Parameters[0]
	if p.Index == nil || *p.Index != 4 || p.Role != "operation-determining" ||
		p.Contributes == nil || p.Contributes.Property != "algorithm" {
		t.Fatalf("AEAD.Lazy.encrypt#5 parameters[0] = %#v, want index=4 operation-determining algorithm", p)
	}

	// LazySodiumJava must resolve to LazySodium, which declares the Lazy/Native
	// interfaces the operations are authored on.
	if parents := kb.Hierarchy["com.goterl.lazysodium.LazySodiumJava"]; len(parents) != 1 || parents[0] != "com.goterl.lazysodium.LazySodium" {
		t.Fatalf("LazySodiumJava hierarchy = %v, want [LazySodium]", parents)
	}
	lazySodiumParents := kb.Hierarchy["com.goterl.lazysodium.LazySodium"]
	for _, want := range []string{
		"com.goterl.lazysodium.interfaces.AEAD.Lazy",
		"com.goterl.lazysodium.interfaces.Box.Lazy",
		"com.goterl.lazysodium.interfaces.GenericHash.Lazy",
		"com.goterl.lazysodium.interfaces.PwHash.Lazy",
		"com.goterl.lazysodium.interfaces.SecretBox.Lazy",
		"com.goterl.lazysodium.interfaces.Sign.Lazy",
	} {
		if !slices.Contains(lazySodiumParents, want) {
			t.Fatalf("LazySodium hierarchy = %v, missing %s", lazySodiumParents, want)
		}
	}
}

// TestLoadEmbeddedJava_SSHClientLifecycle verifies the Java SSH facade
// contracts (scanoss/crypto-finder#201): jsch's JSch/Session/KeyPair/HostKey
// surfaces and sshj's SSHClient/Config/KeyProvider/HostKeyVerifier surfaces. It
// pins the rule anchors, the mandatory producer edges (jsch Session and KeyPair
// have no public constructors), the algorithm-selection config calls, and the
// key-provider and verifier hierarchies.
func TestLoadEmbeddedJava_SSHClientLifecycle(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		want   string
		role   string
		lib    string
	}{
		// jsch rule anchors: JSch.<init>, KeyPair.genKeyPair, KeyPair.load, Session.setConfig.
		{"com.jcraft.jsch.JSch.<init>", 0, "com.jcraft.jsch.JSch", "factory", "jsch"},
		{"com.jcraft.jsch.KeyPair.genKeyPair", 2, "com.jcraft.jsch.KeyPair", "factory", "jsch"},
		{"com.jcraft.jsch.KeyPair.genKeyPair", 3, "com.jcraft.jsch.KeyPair", "factory", "jsch"},
		{"com.jcraft.jsch.KeyPair.load", 2, "com.jcraft.jsch.KeyPair", "factory", "jsch"},
		{"com.jcraft.jsch.KeyPair.load", 3, "com.jcraft.jsch.KeyPair", "factory", "jsch"},
		{"com.jcraft.jsch.Session.setConfig", 2, "void", "config", "jsch"},
		// jsch: getSession is the only Session producer.
		{"com.jcraft.jsch.JSch.getSession", 3, "com.jcraft.jsch.Session", "factory", "jsch"},
		{"com.jcraft.jsch.JSch.setConfig", 2, "void", "config", "jsch"},
		{"com.jcraft.jsch.JSch.setKnownHosts", 1, "void", "config", "jsch"},
		{"com.jcraft.jsch.Session.connect", 0, "void", "operation", "jsch"},
		{"com.jcraft.jsch.Session.getKexAlgorithm", 0, "java.lang.String", "output", "jsch"},
		{"com.jcraft.jsch.Session.getHostKey", 0, "com.jcraft.jsch.HostKey", "output", "jsch"},
		{"com.jcraft.jsch.KeyPair.getSignature", 1, "byte[]", "operation", "jsch"},
		{"com.jcraft.jsch.KeyPair.getFingerPrint", 0, "java.lang.String", "output", "jsch"},
		{"com.jcraft.jsch.KeyPair.writePrivateKey", 1, "void", "output", "jsch"},
		{"com.jcraft.jsch.HostKeyRepository.check", 2, "int", "operation", "jsch"},
		// HostKey.getFingerPrint only exists at arity 1 (it takes the JSch instance).
		{"com.jcraft.jsch.HostKey.getFingerPrint", 1, "java.lang.String", "output", "jsch"},
		// sshj rule anchor plus the connect/auth/key-loading lifecycle.
		{"net.schmizz.sshj.SSHClient.<init>", 0, "net.schmizz.sshj.SSHClient", "factory", "sshj"},
		{"net.schmizz.sshj.SSHClient.<init>", 1, "net.schmizz.sshj.SSHClient", "factory", "sshj"},
		{"net.schmizz.sshj.SocketClient.connect", 2, "void", "operation", "sshj"},
		{"net.schmizz.sshj.SSHClient.addHostKeyVerifier", 1, "void", "config", "sshj"},
		{"net.schmizz.sshj.SSHClient.authPassword", 2, "void", "operation", "sshj"},
		{"net.schmizz.sshj.SSHClient.authPublickey", 2, "void", "operation", "sshj"},
		{"net.schmizz.sshj.SSHClient.loadKeys", 2, "net.schmizz.sshj.userauth.keyprovider.KeyProvider", "factory", "sshj"},
		{"net.schmizz.sshj.SSHClient.getTransport", 0, "net.schmizz.sshj.transport.Transport", "output", "sshj"},
		// sshj algorithm selection lives on Config; there is no
		// setSignatureFactories — setKeyAlgorithms is the signature selector.
		{"net.schmizz.sshj.DefaultConfig.<init>", 0, "net.schmizz.sshj.DefaultConfig", "factory", "sshj"},
		{"net.schmizz.sshj.Config.setCipherFactories", 1, "void", "config", "sshj"},
		{"net.schmizz.sshj.Config.setKeyExchangeFactories", 1, "void", "config", "sshj"},
		{"net.schmizz.sshj.Config.setKeyAlgorithms", 1, "void", "config", "sshj"},
		{"net.schmizz.sshj.ConfigImpl.prioritizeSshRsaKeyAlgorithm", 0, "void", "config", "sshj"},
		// sshj key providers and verifiers.
		{"net.schmizz.sshj.userauth.keyprovider.KeyProvider.getPrivate", 0, "java.security.PrivateKey", "output", "sshj"},
		{"net.schmizz.sshj.userauth.keyprovider.OpenSSHKeyFile.<init>", 0, "net.schmizz.sshj.userauth.keyprovider.OpenSSHKeyFile", "factory", "sshj"},
		{"net.schmizz.sshj.userauth.keyprovider.FileKeyProvider.init", 2, "void", "config", "sshj"},
		{"net.schmizz.sshj.transport.verification.HostKeyVerifier.verify", 3, "boolean", "operation", "sshj"},
		{"net.schmizz.sshj.transport.verification.PromiscuousVerifier.<init>", 0, "net.schmizz.sshj.transport.verification.PromiscuousVerifier", "factory", "sshj"},
		{"net.schmizz.sshj.transport.verification.FingerprintVerifier.getInstance", 1, "net.schmizz.sshj.transport.verification.HostKeyVerifier", "factory", "sshj"},
		{"net.schmizz.sshj.transport.Transport.getSessionID", 0, "byte[]", "output", "sshj"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].Return.Type != tt.want || got[0].Role != tt.role || got[0].SourceLibrary != tt.lib {
				t.Fatalf("%s#%d = %#v, want return %q with role %q from %q", tt.method, tt.arity, got[0], tt.want, tt.role, tt.lib)
			}
		})
	}

	// jsch KeyPair subclasses are all package-private, so the algorithm can only
	// come from the int type argument of genKeyPair — it must be
	// operation-determining, with the key size as metadata.
	genKeyPair := kb.ContractsFor("com.jcraft.jsch.KeyPair.genKeyPair", 3)
	if len(genKeyPair) != 1 || len(genKeyPair[0].Parameters) != 2 {
		t.Fatalf("KeyPair.genKeyPair#3 parameters = %#v, want type and key_size roles", genKeyPair)
	}
	byIndex := map[int]contracts.ParameterContract{}
	for _, p := range genKeyPair[0].Parameters {
		if p.Index != nil {
			byIndex[*p.Index] = p
		}
	}
	if p, ok := byIndex[1]; !ok || p.Role != "operation-determining" || p.Contributes == nil || p.Contributes.Property != "keyType" {
		t.Fatalf("KeyPair.genKeyPair#3 parameters[1] = %#v, want operation-determining keyType", byIndex[1])
	}
	if p, ok := byIndex[2]; !ok || p.Role != "metadata-contributing" || p.Contributes == nil || p.Contributes.Property != "keySize" {
		t.Fatalf("KeyPair.genKeyPair#3 parameters[2] = %#v, want metadata-contributing keySize", byIndex[2])
	}

	// Both libraries' setConfig-style algorithm selection must expose the config
	// key as operation-determining and the value as the algorithm list.
	for _, method := range []string{"com.jcraft.jsch.JSch.setConfig", "com.jcraft.jsch.Session.setConfig"} {
		got := kb.ContractsFor(method, 2)
		if len(got) != 1 || len(got[0].Parameters) != 2 {
			t.Fatalf("%s#2 parameters = %#v, want key and value roles", method, got)
		}
		if got[0].Parameters[0].Role != "operation-determining" || got[0].Parameters[1].Contributes == nil ||
			got[0].Parameters[1].Contributes.Property != "algorithm" {
			t.Fatalf("%s#2 parameters = %#v, want operation-determining key + algorithm value", method, got[0].Parameters)
		}
	}

	// Provider and verifier hierarchies: OpenSSHKeyFile extends PKCS8KeyFile
	// (not BaseFileKeyProvider directly), and SSHClient inherits connect from
	// SocketClient.
	hierarchyWants := map[string]string{
		"net.schmizz.sshj.SSHClient":                                        "net.schmizz.sshj.SocketClient",
		"net.schmizz.sshj.userauth.keyprovider.OpenSSHKeyFile":              "net.schmizz.sshj.userauth.keyprovider.PKCS8KeyFile",
		"net.schmizz.sshj.userauth.keyprovider.PKCS8KeyFile":                "net.schmizz.sshj.userauth.keyprovider.BaseFileKeyProvider",
		"net.schmizz.sshj.transport.verification.PromiscuousVerifier":       "net.schmizz.sshj.transport.verification.HostKeyVerifier",
		"net.schmizz.sshj.transport.verification.ConsoleKnownHostsVerifier": "net.schmizz.sshj.transport.verification.OpenSSHKnownHosts",
		"net.schmizz.sshj.DefaultConfig":                                    "net.schmizz.sshj.ConfigImpl",
	}
	for child, wantParent := range hierarchyWants {
		if parents := kb.Hierarchy[child]; len(parents) == 0 || parents[0] != wantParent {
			t.Fatalf("%s hierarchy = %v, want first parent %s", child, kb.Hierarchy[child], wantParent)
		}
	}
}

// TestLoadEmbeddedJava_OkHttpTLSLifecycle verifies the OkHttp TLS contracts
// (scanoss/crypto-finder#204): certificate pinning, connection-spec cipher and
// TLS-version selection, handshake inspection, the TLS-only slice of
// OkHttpClient.Builder, and the okhttp-tls certificate helpers. It also pins the
// Kotlin-specific shapes that a naive KB would get wrong: @get:JvmName
// accessors are x() not getX(), varargs occupy one parameter slot, and
// ConnectionSpec.Builder has no no-arg constructor.
func TestLoadEmbeddedJava_OkHttpTLSLifecycle(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		want   string
		role   string
	}{
		// Rule anchors: CertificatePinner.Builder.add, ConnectionSpec,
		// ConnectionSpec.Builder.cipherSuites, TlsVersion.
		{"okhttp3.CertificatePinner.Builder.add", 2, "okhttp3.CertificatePinner.Builder", "config"},
		{"okhttp3.CertificatePinner.Builder.build", 0, "okhttp3.CertificatePinner", "factory"},
		{"okhttp3.CertificatePinner.pin", 1, "java.lang.String", "output"},
		{"okhttp3.CertificatePinner.sha256Hash", 1, "okio.ByteString", "operation"},
		{"okhttp3.ConnectionSpec.Builder.cipherSuites", 1, "okhttp3.ConnectionSpec.Builder", "config"},
		{"okhttp3.ConnectionSpec.Builder.tlsVersions", 1, "okhttp3.ConnectionSpec.Builder", "config"},
		{"okhttp3.ConnectionSpec.Builder.build", 0, "okhttp3.ConnectionSpec", "factory"},
		{"okhttp3.ConnectionSpec.isCompatible", 1, "boolean", "operation"},
		{"okhttp3.TlsVersion.forJavaName", 1, "okhttp3.TlsVersion", "factory"},
		{"okhttp3.CipherSuite.forJavaName", 1, "okhttp3.CipherSuite", "factory"},
		// Client TLS configuration.
		{"okhttp3.OkHttpClient.Builder.sslSocketFactory", 2, "okhttp3.OkHttpClient.Builder", "config"},
		{"okhttp3.OkHttpClient.Builder.hostnameVerifier", 1, "okhttp3.OkHttpClient.Builder", "config"},
		{"okhttp3.OkHttpClient.Builder.certificatePinner", 1, "okhttp3.OkHttpClient.Builder", "config"},
		{"okhttp3.OkHttpClient.Builder.connectionSpecs", 1, "okhttp3.OkHttpClient.Builder", "config"},
		{"okhttp3.OkHttpClient.Builder.build", 0, "okhttp3.OkHttpClient", "factory"},
		{"okhttp3.OkHttpClient.x509TrustManager", 0, "javax.net.ssl.X509TrustManager", "output"},
		// Handshake results.
		{"okhttp3.Handshake.get", 1, "okhttp3.Handshake", "factory"},
		{"okhttp3.Handshake.tlsVersion", 0, "okhttp3.TlsVersion", "output"},
		{"okhttp3.Handshake.cipherSuite", 0, "okhttp3.CipherSuite", "output"},
		// okhttp-tls certificate generation.
		{"okhttp3.tls.HeldCertificate.Builder.ecdsa256", 0, "okhttp3.tls.HeldCertificate.Builder", "config"},
		{"okhttp3.tls.HeldCertificate.Builder.rsa2048", 0, "okhttp3.tls.HeldCertificate.Builder", "config"},
		{"okhttp3.tls.HeldCertificate.Builder.signedBy", 1, "okhttp3.tls.HeldCertificate.Builder", "config"},
		{"okhttp3.tls.HeldCertificate.Builder.build", 0, "okhttp3.tls.HeldCertificate", "operation"},
		{"okhttp3.tls.HeldCertificate.privateKeyPkcs8Pem", 0, "java.lang.String", "output"},
		{"okhttp3.tls.HandshakeCertificates.Builder.addInsecureHost", 1, "okhttp3.tls.HandshakeCertificates.Builder", "config"},
		{"okhttp3.tls.HandshakeCertificates.sslContext", 0, "javax.net.ssl.SSLContext", "operation"},
		{"okhttp3.tls.Certificates.decodeCertificatePem", 1, "java.security.cert.X509Certificate", "factory"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].Return.Type != tt.want || got[0].Role != tt.role || got[0].SourceLibrary != "okhttp-tls" {
				t.Fatalf("%s#%d = %#v, want return %q with role %q from okhttp-tls", tt.method, tt.arity, got[0], tt.want, tt.role)
			}
		})
	}

	// Kotlin @get:JvmName means the Java-visible accessors are cipherSuites()
	// and tlsVersions(), never getCipherSuites()/getTlsVersions().
	for _, method := range []string{"okhttp3.ConnectionSpec.cipherSuites", "okhttp3.ConnectionSpec.tlsVersions"} {
		if got := kb.ContractsFor(method, 0); len(got) != 1 || got[0].Return.Type != "java.util.List" {
			t.Fatalf("%s#0 = %#v, want java.util.List", method, got)
		}
	}
	for _, absent := range []string{"okhttp3.ConnectionSpec.getCipherSuites", "okhttp3.ConnectionSpec.getTlsVersions"} {
		if got := kb.ContractsFor(absent, 0); len(got) != 0 {
			t.Fatalf("%s#0 = %#v, want no contract (Kotlin @get:JvmName renames it)", absent, got)
		}
	}

	// ConnectionSpec.Builder is only constructible from a base spec — a no-arg
	// form does not exist and must not be contracted.
	if got := kb.ContractsFor("okhttp3.ConnectionSpec.Builder.<init>", 1); len(got) != 1 {
		t.Fatalf("ConnectionSpec.Builder.<init>#1 contracts = %d, want 1", len(got))
	}
	if got := kb.ContractsFor("okhttp3.ConnectionSpec.Builder.<init>", 0); len(got) != 0 {
		t.Fatalf("ConnectionSpec.Builder.<init>#0 = %#v, want no contract (no no-arg ctor exists)", got)
	}

	// Cipher-suite and TLS-version selection is operation-determining: it picks
	// the algorithms rather than describing them.
	selectors := map[string]string{
		"okhttp3.ConnectionSpec.Builder.cipherSuites": "cipher",
		"okhttp3.ConnectionSpec.Builder.tlsVersions":  "protocolVersion",
	}
	for method, property := range selectors {
		got := kb.ContractsFor(method, 1)
		if len(got) != 1 || len(got[0].Parameters) != 1 {
			t.Fatalf("%s#1 parameters = %#v, want one selector parameter", method, got)
		}
		p := got[0].Parameters[0]
		if p.Role != "operation-determining" || p.Contributes == nil || p.Contributes.Property != property {
			t.Fatalf("%s#1 parameters[0] = %#v, want operation-determining %s", method, p, property)
		}
	}

	// TlsVersion is an enum; CipherSuite deliberately is not (it interns
	// instances through forJavaName).
	if parents := kb.Hierarchy["okhttp3.TlsVersion"]; len(parents) != 1 || parents[0] != "java.lang.Enum" {
		t.Fatalf("TlsVersion hierarchy = %v, want [java.lang.Enum]", parents)
	}
	if parents := kb.Hierarchy["okhttp3.CipherSuite"]; len(parents) != 1 || parents[0] != "java.lang.Object" {
		t.Fatalf("CipherSuite hierarchy = %v, want [java.lang.Object]", parents)
	}
}
