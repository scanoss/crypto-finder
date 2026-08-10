package contracts_test

import (
	"fmt"
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
