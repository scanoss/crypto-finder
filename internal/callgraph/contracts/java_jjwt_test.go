// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// JJWT's contracts are split across era files because a file may only claim
// versions where every entry in it is true (the era table is in
// java/jjwt.yaml). The set is compared exactly, rendering role, return and
// every parameter's role, property and derivation, so a dropped entry, a
// stray one, a flipped parameter role, or an entry moved to a file whose
// range makes it false all fail here.
var wantJjwtContracts = []string{
	"io.jsonwebtoken.JwtBuilder.addClaims#1//io.jsonwebtoken.JwtBuilder/[]/jjwt",
	"io.jsonwebtoken.JwtBuilder.claim#2//io.jsonwebtoken.JwtBuilder/[]/jjwt",
	"io.jsonwebtoken.JwtBuilder.claims#1//io.jsonwebtoken.JwtBuilder/[]/jjwt-0.12",
	"io.jsonwebtoken.JwtBuilder.compact#0/operation/java.lang.String/[]/jjwt",
	"io.jsonwebtoken.JwtBuilder.content#1//io.jsonwebtoken.JwtBuilder/[]/jjwt-0.12",
	"io.jsonwebtoken.JwtBuilder.content#2//io.jsonwebtoken.JwtBuilder/[]/jjwt-0.12",
	"io.jsonwebtoken.JwtBuilder.encryptWith#2/config/io.jsonwebtoken.JwtBuilder/[1:operation-determining:contentEncryption:argument_value]/jjwt-0.12",
	"io.jsonwebtoken.JwtBuilder.encryptWith#3/config/io.jsonwebtoken.JwtBuilder/[1:operation-determining:algorithm:argument_value 2:metadata-contributing:contentEncryption:argument_value]/jjwt-0.12",
	"io.jsonwebtoken.JwtBuilder.expiration#1//io.jsonwebtoken.JwtBuilder/[]/jjwt-0.12",
	"io.jsonwebtoken.JwtBuilder.id#1//io.jsonwebtoken.JwtBuilder/[]/jjwt-0.12",
	"io.jsonwebtoken.JwtBuilder.issuedAt#1//io.jsonwebtoken.JwtBuilder/[]/jjwt-0.12",
	"io.jsonwebtoken.JwtBuilder.issuer#1//io.jsonwebtoken.JwtBuilder/[]/jjwt-0.12",
	"io.jsonwebtoken.JwtBuilder.notBefore#1//io.jsonwebtoken.JwtBuilder/[]/jjwt-0.12",
	"io.jsonwebtoken.JwtBuilder.setAudience#1//io.jsonwebtoken.JwtBuilder/[]/jjwt",
	"io.jsonwebtoken.JwtBuilder.setClaims#1//io.jsonwebtoken.JwtBuilder/[]/jjwt",
	"io.jsonwebtoken.JwtBuilder.setExpiration#1//io.jsonwebtoken.JwtBuilder/[]/jjwt",
	"io.jsonwebtoken.JwtBuilder.setHeader#1//io.jsonwebtoken.JwtBuilder/[]/jjwt",
	"io.jsonwebtoken.JwtBuilder.setHeaderParam#2//io.jsonwebtoken.JwtBuilder/[]/jjwt",
	"io.jsonwebtoken.JwtBuilder.setHeaderParams#1//io.jsonwebtoken.JwtBuilder/[]/jjwt",
	"io.jsonwebtoken.JwtBuilder.setId#1//io.jsonwebtoken.JwtBuilder/[]/jjwt",
	"io.jsonwebtoken.JwtBuilder.setIssuedAt#1//io.jsonwebtoken.JwtBuilder/[]/jjwt",
	"io.jsonwebtoken.JwtBuilder.setIssuer#1//io.jsonwebtoken.JwtBuilder/[]/jjwt",
	"io.jsonwebtoken.JwtBuilder.setNotBefore#1//io.jsonwebtoken.JwtBuilder/[]/jjwt",
	"io.jsonwebtoken.JwtBuilder.setPayload#1//io.jsonwebtoken.JwtBuilder/[]/jjwt",
	"io.jsonwebtoken.JwtBuilder.setSubject#1//io.jsonwebtoken.JwtBuilder/[]/jjwt",
	"io.jsonwebtoken.JwtBuilder.signWith#1/config/io.jsonwebtoken.JwtBuilder/[]/jjwt",
	"io.jsonwebtoken.JwtBuilder.signWith#2/config/io.jsonwebtoken.JwtBuilder/[]/jjwt",
	"io.jsonwebtoken.JwtBuilder.subject#1//io.jsonwebtoken.JwtBuilder/[]/jjwt-0.12",
	"io.jsonwebtoken.JwtParser.parseClaimsJws#1/operation/io.jsonwebtoken.Jws/[]/jjwt",
	"io.jsonwebtoken.JwtParser.parseEncryptedClaims#1/operation/io.jsonwebtoken.Jwe/[]/jjwt-0.12",
	"io.jsonwebtoken.JwtParser.parseEncryptedContent#1/operation/io.jsonwebtoken.Jwe/[]/jjwt-0.12",
	"io.jsonwebtoken.JwtParser.parseSignedClaims#1/operation/io.jsonwebtoken.Jws/[]/jjwt-0.12",
	"io.jsonwebtoken.JwtParser.parseSignedClaims#2/operation/io.jsonwebtoken.Jws/[]/jjwt-0.12",
	"io.jsonwebtoken.JwtParser.parseSignedContent#1/operation/io.jsonwebtoken.Jws/[]/jjwt-0.12",
	"io.jsonwebtoken.JwtParser.parseSignedContent#2/operation/io.jsonwebtoken.Jws/[]/jjwt-0.12",
	"io.jsonwebtoken.JwtParser.setSigningKey#1/config/io.jsonwebtoken.JwtParser/[]/jjwt-0.10",
	"io.jsonwebtoken.JwtParserBuilder.build#0/factory/io.jsonwebtoken.JwtParser/[]/jjwt-0.11",
	"io.jsonwebtoken.JwtParserBuilder.decryptWith#1/config/io.jsonwebtoken.JwtParserBuilder/[]/jjwt-0.12",
	"io.jsonwebtoken.JwtParserBuilder.setSigningKey#1/config/io.jsonwebtoken.JwtParserBuilder/[]/jjwt-0.11",
	"io.jsonwebtoken.JwtParserBuilder.verifyWith#1/config/io.jsonwebtoken.JwtParserBuilder/[]/jjwt-0.12",
	"io.jsonwebtoken.Jwts.builder#0/factory/io.jsonwebtoken.JwtBuilder/[]/jjwt",
	"io.jsonwebtoken.Jwts.parser#0/factory/io.jsonwebtoken.JwtParserBuilder/[]/jjwt-0.12",
	"io.jsonwebtoken.Jwts.parserBuilder#0/factory/io.jsonwebtoken.JwtParserBuilder/[]/jjwt-0.11.0",
	"io.jsonwebtoken.security.KeyBuilder.build#0/factory/java.security.Key/[]/jjwt-0.12",
	"io.jsonwebtoken.security.KeyBuilderSupplier.key#0/factory/io.jsonwebtoken.security.KeyBuilder/[]/jjwt-0.12",
	"io.jsonwebtoken.security.KeyPairBuilder.build#0/factory/java.security.KeyPair/[]/jjwt-0.12",
	"io.jsonwebtoken.security.KeyPairBuilderSupplier.keyPair#0/factory/io.jsonwebtoken.security.KeyPairBuilder/[]/jjwt-0.12",
	"io.jsonwebtoken.security.Keys.hmacShaKeyFor#1/factory/javax.crypto.SecretKey/[0:metadata-contributing:keySize:argument_bit_length]/jjwt",
	"io.jsonwebtoken.security.Keys.keyPairFor#1/factory/java.security.KeyPair/[0:operation-determining:algorithm:argument_value]/jjwt",
	"io.jsonwebtoken.security.Keys.secretKeyFor#1/factory/javax.crypto.SecretKey/[0:operation-determining:algorithm:argument_value]/jjwt",
	"io.jsonwebtoken.security.SecretKeyBuilder.build#0/factory/javax.crypto.SecretKey/[]/jjwt-0.12",
}

func TestLoadEmbeddedJavaJjwtContractsExactSet(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	var got []string
	for _, list := range kb.Contracts {
		for i := range list {
			c := &list[i]
			if c.SourceLibrary != "jjwt" && !strings.HasPrefix(c.SourceLibrary, "jjwt-") {
				continue
			}
			var params []string
			for _, p := range c.Parameters {
				if p.Index == nil || p.Contributes == nil {
					t.Errorf("%s#%d: parameter %+v has no index or contribution", c.Method, c.Arity, p)
					continue
				}
				params = append(params, fmt.Sprintf("%d:%s:%s:%s", *p.Index, p.Role, p.Contributes.Property, p.Contributes.Derivation))
			}
			got = append(got, fmt.Sprintf("%s#%d/%s/%s/[%s]/%s",
				c.Method, c.Arity, c.Role, c.Return.Type, strings.Join(params, " "), c.SourceLibrary))
		}
	}

	for _, g := range got {
		if !slices.Contains(wantJjwtContracts, g) {
			t.Errorf("unexpected jjwt contract: %s", g)
		}
	}
	for _, w := range wantJjwtContracts {
		if !slices.Contains(got, w) {
			t.Errorf("missing jjwt contract:    %s", w)
		}
	}
}
