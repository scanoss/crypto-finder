package callgraph

import (
	"slices"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The bctls, bcmls and bcmail contracts key on the identity the Java parser
// gives each call: a TLS and a DTLS handshake, a BCJSSE-backed SSLContext, an
// MLS suite selected by its RFC 9420 identifier, and an S/MIME message signed,
// enveloped and parsed back.
func TestBouncyCastleModuleContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	calls := parseJavaCallArities(t, `package app;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import javax.crypto.SecretKey;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;
import javax.net.ssl.SSLContext;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.mail.smime.SMIMEAuthEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSRequest;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.TlsClient;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.tls.TlsServerProtocol;

public class App {
    public void tls(InputStream in, OutputStream out, TlsClient client, TlsServer server) throws Exception {
        TlsClientProtocol c = new TlsClientProtocol(in, out);
        c.connect(client);
        TlsServerProtocol s = new TlsServerProtocol(in, out);
        s.accept(server);
        new TlsClientProtocol();
        new TlsServerProtocol();
    }

    public void dtls(TlsClient client, TlsServer server, DatagramTransport transport, DTLSRequest request) throws Exception {
        DTLSClientProtocol c = new DTLSClientProtocol();
        c.connect(client, transport);
        DTLSServerProtocol s = new DTLSServerProtocol();
        s.accept(server, transport);
        s.accept(server, transport, request);
    }

    public SSLContext jsse() throws Exception {
        Security.addProvider(new BouncyCastleJsseProvider());
        return SSLContext.getInstance("TLSv1.3", "BCJSSE");
    }

    public byte[] mls(byte[] priv, byte[] content, AsymmetricCipherKeyPair key) throws Exception {
        MlsCipherSuite suite = MlsCipherSuite.getSuite(MlsCipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
        suite.generateSignatureKeyPair();
        suite.hash(content);
        suite.deserializeSignaturePrivateKey(priv);
        suite.serializeSignaturePrivateKey(key.getPrivate());
        suite.serializeSignaturePublicKey(key.getPublic());
        return suite.signWithLabel(priv, "label", content);
    }

    public void smime(MimeBodyPart part, SignerInfoGenerator signer, JcaCertStore certs,
            RecipientInfoGenerator recipient, OutputEncryptor encryptor, MimeMultipart signed) throws Exception {
        SMIMESignedGenerator gen = new SMIMESignedGenerator();
        gen.addSignerInfoGenerator(signer);
        gen.addCertificates(certs);
        gen.generate(part);
        SMIMEEnvelopedGenerator env = new SMIMEEnvelopedGenerator();
        env.addRecipientInfoGenerator(recipient);
        env.generate(part, encryptor);
        SMIMEAuthEnvelopedGenerator gcm = new SMIMEAuthEnvelopedGenerator();
        gcm.addRecipientInfoGenerator(recipient);
        new SMIMESigned(signed);
        SMIMESigned.getSafeInstance(signed);
        SMIMESigned.getSafeInstance(signed, "binary");
        new SMIMEEnveloped(part);
    }

    public void legacySmime(MimeBodyPart part, PrivateKey key, X509Certificate cert, AttributeTable signedAttrs,
            AttributeTable unsignedAttrs, PublicKey pub, byte[] keyId, SecretKey kek) throws Exception {
        SMIMESignedGenerator gen = new SMIMESignedGenerator();
        gen.addSigner(key, cert, SMIMESignedGenerator.DIGEST_SHA256);
        gen.addSigner(key, cert, SMIMESignedGenerator.ENCRYPTION_RSA, SMIMESignedGenerator.DIGEST_SHA256);
        gen.addSigner(key, cert, SMIMESignedGenerator.DIGEST_SHA256, signedAttrs, unsignedAttrs);
        gen.addSigner(key, cert, SMIMESignedGenerator.ENCRYPTION_RSA, SMIMESignedGenerator.DIGEST_SHA256, signedAttrs, unsignedAttrs);
        gen.generate(part, "BC");
        gen.generateEncapsulated(part, "BC");
        SMIMEEnvelopedGenerator env = new SMIMEEnvelopedGenerator();
        env.addKeyTransRecipient(cert);
        env.addKeyTransRecipient(pub, keyId);
        env.addKEKRecipient(kek, keyId);
        env.addKeyAgreementRecipient("ECDH", key, pub, cert, "AESWRAP", "BC");
        env.generate(part, SMIMEEnvelopedGenerator.AES128_CBC, "BC");
        env.generate(part, SMIMEEnvelopedGenerator.RC2_CBC, 40, "BC");
    }
}
`)

	for _, tc := range []struct {
		method  string
		arity   int
		role    string
		library string
	}{
		{"org.bouncycastle.tls.TlsClientProtocol.<init>", 2, "factory", "bouncycastle-tls"},
		{"org.bouncycastle.tls.TlsClientProtocol.<init>", 0, "factory", "bouncycastle-tls"},
		{"org.bouncycastle.tls.TlsClientProtocol.connect", 1, "operation", "bouncycastle-tls"},
		{"org.bouncycastle.tls.TlsServerProtocol.<init>", 2, "factory", "bouncycastle-tls"},
		{"org.bouncycastle.tls.TlsServerProtocol.<init>", 0, "factory", "bouncycastle-tls"},
		{"org.bouncycastle.tls.TlsServerProtocol.accept", 1, "operation", "bouncycastle-tls"},
		{"org.bouncycastle.tls.DTLSClientProtocol.<init>", 0, "factory", "bouncycastle-tls-1.58"},
		{"org.bouncycastle.tls.DTLSClientProtocol.connect", 2, "operation", "bouncycastle-tls"},
		{"org.bouncycastle.tls.DTLSServerProtocol.<init>", 0, "factory", "bouncycastle-tls-1.58"},
		{"org.bouncycastle.tls.DTLSServerProtocol.accept", 2, "operation", "bouncycastle-tls"},
		{"org.bouncycastle.jsse.provider.BouncyCastleJsseProvider.<init>", 0, "factory", "bouncycastle-tls"},
		{"javax.net.ssl.SSLContext.getInstance", 2, "factory", "jdk-crypto"},
		{"org.bouncycastle.mls.crypto.MlsCipherSuite.getSuite", 1, "factory", "bouncycastle-mls"},
		{"org.bouncycastle.mls.crypto.MlsCipherSuite.generateSignatureKeyPair", 0, "factory", "bouncycastle-mls"},
		{"org.bouncycastle.mls.crypto.MlsCipherSuite.hash", 1, "operation", "bouncycastle-mls"},
		{"org.bouncycastle.mls.crypto.MlsCipherSuite.signWithLabel", 3, "operation", "bouncycastle-mls"},
		{"org.bouncycastle.mail.smime.SMIMESignedGenerator.<init>", 0, "factory", "bouncycastle-smime"},
		{"org.bouncycastle.mail.smime.SMIMESignedGenerator.addSignerInfoGenerator", 1, "config", "bouncycastle-smime"},
		{"org.bouncycastle.mail.smime.SMIMESignedGenerator.addCertificates", 1, "config", "bouncycastle-smime"},
		{"org.bouncycastle.mail.smime.SMIMESignedGenerator.generate", 1, "operation", "bouncycastle-smime"},
		{"org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator.<init>", 0, "factory", "bouncycastle-smime"},
		{"org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator.addRecipientInfoGenerator", 1, "config", "bouncycastle-smime"},
		{"org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator.generate", 2, "operation", "bouncycastle-smime"},
		{"org.bouncycastle.mail.smime.SMIMEAuthEnvelopedGenerator.<init>", 0, "factory", "bouncycastle-smime-1.80"},
		{"org.bouncycastle.mail.smime.SMIMEAuthEnvelopedGenerator.addRecipientInfoGenerator", 1, "config", "bouncycastle-smime-1.80"},
		{"org.bouncycastle.mail.smime.SMIMESigned.<init>", 1, "factory", "bouncycastle-smime"},
		{"org.bouncycastle.mail.smime.SMIMEEnveloped.<init>", 1, "factory", "bouncycastle-smime"},
		{"org.bouncycastle.tls.DTLSServerProtocol.accept", 3, "operation", "bouncycastle-tls-1.62"},
		{"org.bouncycastle.mls.crypto.MlsCipherSuite.deserializeSignaturePrivateKey", 1, "factory", "bouncycastle-mls"},
		{"org.bouncycastle.mls.crypto.MlsCipherSuite.serializeSignaturePrivateKey", 1, "output", "bouncycastle-mls"},
		{"org.bouncycastle.mls.crypto.MlsCipherSuite.serializeSignaturePublicKey", 1, "output", "bouncycastle-mls"},
		{"org.bouncycastle.mail.smime.SMIMESigned.getSafeInstance", 1, "factory", "bouncycastle-smime-1.84"},
		{"org.bouncycastle.mail.smime.SMIMESigned.getSafeInstance", 2, "factory", "bouncycastle-smime-1.84"},
		{"org.bouncycastle.mail.smime.SMIMESignedGenerator.addSigner", 3, "config", "bouncycastle-smime-1.46"},
		{"org.bouncycastle.mail.smime.SMIMESignedGenerator.addSigner", 4, "config", "bouncycastle-smime-1.46"},
		{"org.bouncycastle.mail.smime.SMIMESignedGenerator.addSigner", 5, "config", "bouncycastle-smime-1.46"},
		{"org.bouncycastle.mail.smime.SMIMESignedGenerator.addSigner", 6, "config", "bouncycastle-smime-1.46"},
		{"org.bouncycastle.mail.smime.SMIMESignedGenerator.generate", 2, "operation", "bouncycastle-smime-1.46"},
		{"org.bouncycastle.mail.smime.SMIMESignedGenerator.generateEncapsulated", 2, "operation", "bouncycastle-smime-1.46"},
		{"org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator.addKeyTransRecipient", 1, "config", "bouncycastle-smime-1.46"},
		{"org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator.addKeyTransRecipient", 2, "config", "bouncycastle-smime-1.46"},
		{"org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator.addKEKRecipient", 2, "config", "bouncycastle-smime-1.46"},
		{"org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator.addKeyAgreementRecipient", 6, "config", "bouncycastle-smime-1.46"},
		{"org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator.generate", 3, "operation", "bouncycastle-smime-1.46"},
		{"org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator.generate", 4, "operation", "bouncycastle-smime-1.46"},
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

// Stream plumbing on the same engines and the MLS suite's own accessors are
// not cryptographic operations, so they resolve to nothing.
func TestBouncyCastleModuleContractsIgnoreNonCryptoCalls(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	calls := parseJavaCallArities(t, `package app;

import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.tls.TlsClientProtocol;

public class App {
    public Object plumbing(TlsClientProtocol c, MlsCipherSuite suite) throws Exception {
        c.getInputStream();
        c.close();
        return suite.getSuiteID();
    }
}
`)

	for _, method := range []string{
		"org.bouncycastle.tls.TlsClientProtocol.getInputStream",
		"org.bouncycastle.tls.TlsClientProtocol.close",
		"org.bouncycastle.mls.crypto.MlsCipherSuite.getSuiteID",
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

// The MLS suite identifier selects the KEM, AEAD, hash and signature scheme
// together, and SSLContext.getInstance names the protocol and, for BCJSSE, the
// provider that routes the context to Bouncy Castle.
func TestBouncyCastleModuleContractsReportSuiteProtocolAndProvider(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	for _, tc := range []struct {
		method   string
		arity    int
		index    int
		role     string
		property string
	}{
		{"org.bouncycastle.mls.crypto.MlsCipherSuite.getSuite", 1, 0, "operation-determining", "algorithm"},
		{"javax.net.ssl.SSLContext.getInstance", 1, 0, "operation-determining", "protocolVersion"},
		{"javax.net.ssl.SSLContext.getInstance", 2, 0, "operation-determining", "protocolVersion"},
		{"javax.net.ssl.SSLContext.getInstance", 2, 1, "metadata-contributing", "provider"},
	} {
		got := kb.ContractsForTolerant(tc.method, tc.arity)
		if len(got) != 1 {
			t.Errorf("ContractsForTolerant(%q, %d) = %d, want exactly one", tc.method, tc.arity, len(got))
			continue
		}
		var found bool
		for _, p := range got[0].Parameters {
			if p.Index == nil || *p.Index != tc.index {
				continue
			}
			found = true
			if p.Role != tc.role || p.Contributes == nil || p.Contributes.Property != tc.property {
				t.Errorf("%s/%d: parameters[%d] = role %q contributes %#v, want %q %q",
					tc.method, tc.arity, tc.index, p.Role, p.Contributes, tc.role, tc.property)
			}
		}
		if !found {
			t.Errorf("%s/%d: no parameter entry at index %d", tc.method, tc.arity, tc.index)
		}
	}
}
