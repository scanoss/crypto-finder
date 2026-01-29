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
