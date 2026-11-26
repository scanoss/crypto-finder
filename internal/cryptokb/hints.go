package cryptokb

import "github.com/scanoss/reach/callgraph/contracts"

// hints is the crypto domain's language-level knowledge (contracts.Hints).
var hints = contracts.Hints{
	// The JCA/JCE classes a crypto scan must type even when a file
	// wildcard-imports several packages that could declare the name.
	JavaWildcardTypePackages: map[string]string{
		"CertificateFactory": "java.security.cert",
		"Cipher":             "javax.crypto",
		"GCMParameterSpec":   "javax.crypto.spec",
		"IvParameterSpec":    "javax.crypto.spec",
		"KeyAgreement":       "javax.crypto",
		"KeyFactory":         "java.security",
		"KeyGenerator":       "javax.crypto",
		"KeyPairGenerator":   "java.security",
		"KeyStore":           "java.security",
		"Mac":                "javax.crypto",
		"MessageDigest":      "java.security",
		"SecretKeyFactory":   "javax.crypto",
		"SecretKeySpec":      "javax.crypto.spec",
		"SecureRandom":       "java.security",
		"Signature":          "java.security",
	},
	// A method declared to return the JCA Key supertype says too little:
	// inference refines it to the concrete key its body returns.
	InferenceTriggerTypes: map[string]struct{}{
		"Key":               {},
		"java.security.Key": {},
	},
}
