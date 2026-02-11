// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package converter

// OID Constants for Cryptographic Algorithms.
//
// This file contains Object Identifier (OID) constants for cryptographic algorithms
// used in CycloneDX CBOM generation. OIDs are sourced from:
//
// NIST Computer Security Objects Register (CSOR):
//   - https://csrc.nist.gov/projects/computer-security-objects-register
//   - Base OID: 2.16.840.1.101.3.4 (nistAlgorithm)
//
// PKCS #1 (RSA Cryptography Specifications):
//   - RFC 8017
//   - Base OID: 1.2.840.113549.1.1 (pkcs-1)
//
// ANSI X9.62 (Elliptic Curve Digital Signature Algorithm):
//   - Base OID: 1.2.840.10045 (ansi-X9-62)
//
// OIW (Open Systems Environment Implementors' Workshop) - Legacy:
//   - Base OID: 1.3.14.3.2 (secsig/algorithms)

// NIST CSOR Algorithm Base OIDs.
const (
	// OIDNISTAlgorithm is the base OID for NIST cryptographic algorithms.
	// {joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4)}.
	OIDNISTAlgorithm = "2.16.840.1.101.3.4"

	// OIDAES is the parent OID for Advanced Encryption Standard algorithms.
	// {nistAlgorithm(4) aes(1)}.
	OIDAES = OIDNISTAlgorithm + ".1"

	// OIDHashAlgs is the parent OID for Secure Hash Algorithms.
	// {nistAlgorithm(4) hashAlgs(2)}.
	OIDHashAlgs = OIDNISTAlgorithm + ".2"

	// OIDSigAlgs is the parent OID for Signature Algorithms.
	// {nistAlgorithm(4) sigAlgs(3)}.
	OIDSigAlgs = OIDNISTAlgorithm + ".3"
)

// NIST CSOR AES Algorithm OIDs (2.16.840.1.101.3.4.1.*).
// AES-128 variants.
const (
	OIDAES128ECB     = OIDAES + ".1" // aes128-ECB
	OIDAES128CBC     = OIDAES + ".2" // aes128-CBC
	OIDAES128OFB     = OIDAES + ".3" // aes128-OFB
	OIDAES128CFB     = OIDAES + ".4" // aes128-CFB
	OIDAES128WRAP    = OIDAES + ".5" // id-aes128-wrap
	OIDAES128GCM     = OIDAES + ".6" // aes128-GCM
	OIDAES128CCM     = OIDAES + ".7" // aes128-CCM
	OIDAES128WRAPPAD = OIDAES + ".8" // aes128-wrap-pad
)

// NIST CSOR AES-192 variants (2.16.840.1.101.3.4.1.2x).
const (
	OIDAES192ECB     = OIDAES + ".21" // aes192-ECB
	OIDAES192CBC     = OIDAES + ".22" // aes192-CBC
	OIDAES192OFB     = OIDAES + ".23" // aes192-OFB
	OIDAES192CFB     = OIDAES + ".24" // aes192-CFB
	OIDAES192WRAP    = OIDAES + ".25" // id-aes192-wrap
	OIDAES192GCM     = OIDAES + ".26" // aes192-GCM
	OIDAES192CCM     = OIDAES + ".27" // aes192-CCM
	OIDAES192WRAPPAD = OIDAES + ".28" // aes192-wrap-pad
)

// NIST CSOR AES-256 variants (2.16.840.1.101.3.4.1.4x).
const (
	OIDAES256ECB     = OIDAES + ".41" // aes256-ECB
	OIDAES256CBC     = OIDAES + ".42" // aes256-CBC
	OIDAES256OFB     = OIDAES + ".43" // aes256-OFB
	OIDAES256CFB     = OIDAES + ".44" // aes256-CFB
	OIDAES256WRAP    = OIDAES + ".45" // id-aes256-wrap
	OIDAES256GCM     = OIDAES + ".46" // aes256-GCM
	OIDAES256CCM     = OIDAES + ".47" // aes256-CCM
	OIDAES256WRAPPAD = OIDAES + ".48" // aes256-wrap-pad
)

// NIST CSOR SHA-2 Algorithm OIDs (2.16.840.1.101.3.4.2.1-6).
const (
	OIDSHA256    = OIDHashAlgs + ".1" // SHA-256
	OIDSHA384    = OIDHashAlgs + ".2" // SHA-384
	OIDSHA512    = OIDHashAlgs + ".3" // SHA-512
	OIDSHA224    = OIDHashAlgs + ".4" // SHA-224
	OIDSHA512224 = OIDHashAlgs + ".5" // SHA-512/224
	OIDSHA512256 = OIDHashAlgs + ".6" // SHA-512/256
)

// NIST CSOR SHA-3 Algorithm OIDs (2.16.840.1.101.3.4.2.7-10).
const (
	OIDSHA3224 = OIDHashAlgs + ".7"  // SHA3-224
	OIDSHA3256 = OIDHashAlgs + ".8"  // SHA3-256
	OIDSHA3384 = OIDHashAlgs + ".9"  // SHA3-384
	OIDSHA3512 = OIDHashAlgs + ".10" // SHA3-512
)

// NIST CSOR SHAKE Algorithm OIDs (2.16.840.1.101.3.4.2.11-12).
const (
	OIDSHAKE128 = OIDHashAlgs + ".11" // SHAKE128 extendable-output function
	OIDSHAKE256 = OIDHashAlgs + ".12" // SHAKE256 extendable-output function
)

// NIST CSOR DSA Signature Algorithm OIDs (2.16.840.1.101.3.4.3.*).
const (
	OIDDSASHA224 = OIDSigAlgs + ".1" // dsa-with-sha224
	OIDDSASHA256 = OIDSigAlgs + ".2" // dsa-with-sha256
)

// PKCS #1 RSA Algorithm OIDs (1.2.840.113549.1.1.*).
// Source: RFC 8017.
const (
	OIDPKCS1     = "1.2.840.113549.1.1"
	OIDRSA       = OIDPKCS1 + ".1"  // rsaEncryption
	OIDRSAMD5    = OIDPKCS1 + ".4"  // md5WithRSAEncryption
	OIDRSASHA1   = OIDPKCS1 + ".5"  // sha1WithRSAEncryption
	OIDRSASHA256 = OIDPKCS1 + ".11" // sha256WithRSAEncryption
	OIDRSASHA384 = OIDPKCS1 + ".12" // sha384WithRSAEncryption
	OIDRSASHA512 = OIDPKCS1 + ".13" // sha512WithRSAEncryption
	OIDRSASHA224 = OIDPKCS1 + ".14" // sha224WithRSAEncryption
)

// ANSI X9.62 ECDSA Algorithm OIDs (1.2.840.10045.*).
// Source: ANSI X9.62-2005.
const (
	OIDANSIX962    = "1.2.840.10045"
	OIDECPublicKey = OIDANSIX962 + ".2.1"   // ecPublicKey
	OIDECDSASHA1   = OIDANSIX962 + ".4.1"   // ecdsa-with-SHA1
	OIDECDSASHA224 = OIDANSIX962 + ".4.3.1" // ecdsa-with-SHA224
	OIDECDSASHA256 = OIDANSIX962 + ".4.3.2" // ecdsa-with-SHA256
	OIDECDSASHA384 = OIDANSIX962 + ".4.3.3" // ecdsa-with-SHA384
	OIDECDSASHA512 = OIDANSIX962 + ".4.3.4" // ecdsa-with-SHA512
)

// HMAC Algorithm OIDs (1.2.840.113549.2.*).
// Source: RFC 8018.
const (
	OIDHMACBase   = "1.2.840.113549.2"
	OIDHMACMD5    = OIDHMACBase + ".6"  // hmacWithMD5
	OIDHMACSHA1   = OIDHMACBase + ".7"  // hmacWithSHA1
	OIDHMACSHA224 = OIDHMACBase + ".8"  // hmacWithSHA224
	OIDHMACSHA256 = OIDHMACBase + ".9"  // hmacWithSHA256
	OIDHMACSHA384 = OIDHMACBase + ".10" // hmacWithSHA384
	OIDHMACSHA512 = OIDHMACBase + ".11" // hmacWithSHA512
)

// NIST CSOR KEM Algorithm Base OID (2.16.840.1.101.3.4.4).
const (
	// OIDKEMs is the parent OID for Key Encapsulation Mechanisms.
	// {nistAlgorithm(4) kems(4)}.
	OIDKEMs = OIDNISTAlgorithm + ".4"
)

// NIST CSOR ML-DSA (Module-Lattice Digital Signature Algorithm) OIDs (2.16.840.1.101.3.4.3.17-19).
// Source: RFC 9881, FIPS 204.
const (
	OIDMLDSA44 = OIDSigAlgs + ".17" // ML-DSA-44
	OIDMLDSA65 = OIDSigAlgs + ".18" // ML-DSA-65
	OIDMLDSA87 = OIDSigAlgs + ".19" // ML-DSA-87
)

// NIST CSOR ML-KEM (Module-Lattice Key Encapsulation Mechanism) OIDs (2.16.840.1.101.3.4.4.1-3).
// Source: NIST CSOR, FIPS 203.
const (
	OIDMLKEM512  = OIDKEMs + ".1" // ML-KEM-512
	OIDMLKEM768  = OIDKEMs + ".2" // ML-KEM-768
	OIDMLKEM1024 = OIDKEMs + ".3" // ML-KEM-1024
)

// NIST CSOR SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) OIDs (2.16.840.1.101.3.4.3.20-31).
// Source: RFC 9814/9909, FIPS 205.
const (
	OIDSLHDSASHA2128s  = OIDSigAlgs + ".20" // SLH-DSA-SHA2-128s
	OIDSLHDSASHA2128f  = OIDSigAlgs + ".21" // SLH-DSA-SHA2-128f
	OIDSLHDSASHA2192s  = OIDSigAlgs + ".22" // SLH-DSA-SHA2-192s
	OIDSLHDSASHA2192f  = OIDSigAlgs + ".23" // SLH-DSA-SHA2-192f
	OIDSLHDSASHA2256s  = OIDSigAlgs + ".24" // SLH-DSA-SHA2-256s
	OIDSLHDSASHA2256f  = OIDSigAlgs + ".25" // SLH-DSA-SHA2-256f
	OIDSLHDSASHAKE128s = OIDSigAlgs + ".26" // SLH-DSA-SHAKE-128s
	OIDSLHDSASHAKE128f = OIDSigAlgs + ".27" // SLH-DSA-SHAKE-128f
	OIDSLHDSASHAKE192s = OIDSigAlgs + ".28" // SLH-DSA-SHAKE-192s
	OIDSLHDSASHAKE192f = OIDSigAlgs + ".29" // SLH-DSA-SHAKE-192f
	OIDSLHDSASHAKE256s = OIDSigAlgs + ".30" // SLH-DSA-SHAKE-256s
	OIDSLHDSASHAKE256f = OIDSigAlgs + ".31" // SLH-DSA-SHAKE-256f
)

// RSA additional algorithm OIDs (PKCS#1).
const (
	OIDRSAOAEP = OIDPKCS1 + ".7" // rsaes-oaep (RSAES-OAEP)
)

// PKCS#5 Key Derivation OIDs (1.2.840.113549.1.5.*).
// Source: RFC 2898 (PKCS#5 v2.1).
const (
	OIDPKCS5  = "1.2.840.113549.1.5"
	OIDPBKDF2 = OIDPKCS5 + ".12" // PBKDF2
)

// RSA Digest Algorithm OIDs (1.2.840.113549.2.*).
// Source: RFC 1321 (MD5), RFC 1320 (MD4).
const (
	OIDRSADigestAlgorithm = "1.2.840.113549.2"
	OIDMD4                = OIDRSADigestAlgorithm + ".4" // MD4
	OIDMD5                = OIDRSADigestAlgorithm + ".5" // MD5
)

// scrypt OID (1.3.6.1.4.1.11591.4.11).
// Source: RFC 7914.
const (
	OIDScrypt = "1.3.6.1.4.1.11591.4.11"
)

// Curve25519/Curve448 Algorithm OIDs (1.3.101.*).
// Source: RFC 8410.
const (
	OIDCurves25519448 = "1.3.101"
	OIDX25519         = OIDCurves25519448 + ".110" // X25519 (ECDH)
	OIDX448           = OIDCurves25519448 + ".111" // X448 (ECDH)
	OIDEd25519        = OIDCurves25519448 + ".112" // Ed25519 (EdDSA)
	OIDEd448          = OIDCurves25519448 + ".113" // Ed448 (EdDSA)
)

// ANSI X9.42 Diffie-Hellman OIDs (1.2.840.10046.2.1).
// Source: RFC 2631.
const (
	OIDANSIX942 = "1.2.840.10046"
	OIDDH       = OIDANSIX942 + ".2.1" // dhPublicNumber (FFDH)
)

// SM2/SM3 Chinese National Standard Algorithm OIDs.
// Source: GB/T 32918 (SM2), GB/T 32905 (SM3).
const (
	OIDSM2 = "1.2.156.10197.1.501" // SM2 with SM3
	OIDSM3 = "1.2.156.10197.1.401" // SM3 hash
)

// RC4 Algorithm OID (1.2.840.113549.3.4).
// Source: RSA PKCS (deprecated cipher).
const (
	OIDRSAEncryptionAlgorithm = "1.2.840.113549.3"
	OIDRC4                    = OIDRSAEncryptionAlgorithm + ".4" // RC4 (arcfour)
)

// OIW SECSIG Legacy Algorithm OIDs (1.3.14.3.2.*).
// Source: OIW Security Special Interest Group (deprecated algorithms).
const (
	OIDOIWSECSIG   = "1.3.14.3.2"
	OIDMD4WithRSA  = OIDOIWSECSIG + ".2"  // md5WithRSA (OIW uses this for MD4 too)
	OIDMD5WithRSA  = OIDOIWSECSIG + ".3"  // md5WithRSA
	OIDDESECB      = OIDOIWSECSIG + ".6"  // desECB
	OIDDESCDC      = OIDOIWSECSIG + ".7"  // desCBC
	OIDDESOFB      = OIDOIWSECSIG + ".8"  // desOFB
	OIDDESCFB      = OIDOIWSECSIG + ".9"  // desCFB
	OIDDESEDE      = OIDOIWSECSIG + ".17" // desEDE (Triple DES)
	OIDSHA         = OIDOIWSECSIG + ".18" // sha (original SHA, now SHA-0)
	OIDSHA1        = OIDOIWSECSIG + ".26" // sha-1 (hashAlgorithmIdentifier)
	OIDSHA1WithRSA = OIDOIWSECSIG + ".29" // sha-1WithRSAEncryption
	OIDDSA         = OIDOIWSECSIG + ".12" // dsa
	OIDDSAWithSHA  = OIDOIWSECSIG + ".13" // dsaWithSHA
	OIDDSAWithSHA1 = OIDOIWSECSIG + ".27" // dsaWithSHA1
)

// HSS/LMS (Leighton-Micali Signature) Algorithm OID (1.2.840.113549.1.9.16.3.17).
// Source: RFC 8554 (LMS), RFC 8708 (HSS/LMS in CMS). https://www.rfc-editor.org/rfc/rfc8708.html.
const (
	OIDSMIMEAlg = "1.2.840.113549.1.9.16.3"
	OIDLMS      = OIDSMIMEAlg + ".17" // id-alg-hss-lms-hashsig
)
