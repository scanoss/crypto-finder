// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// selfsigned's shape: the consumer names its binding `forge`, and the parser
// keys every call by the module that binding came from, `node-forge`. The
// contracts must be keyed the same way for any of these calls to carry a role.
const nodeForgeSelfSigned = `const forge = require('node-forge');

function makeCert(attrs, keys) {
  const cert = forge.pki.createCertificate();
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey);
  return cert;
}

function trust(cert) {
  const caStore = forge.pki.createCaStore();
  caStore.addCertificate(cert);
  return caStore;
}

module.exports = { makeCert, trust };
`

// acme-client's shape: a certification request configured, then signed.
const nodeForgeCSR = `const nf = require('node-forge');

function csrFor(attrs, keys) {
  const csr = nf.pki.createCertificationRequest();
  csr.setSubject(attrs);
  csr.setAttributes([]);
  csr.sign(keys.privateKey);
  return csr;
}

module.exports = { csrFor };
`

func TestNodeForgeSupportingCallsCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, file, src string
		asset           entities.CryptographicAsset
		want            map[string]string
	}{
		{
			name: "certificate built on a binding named forge",
			file: "cert.js",
			src:  nodeForgeSelfSigned,
			asset: cAsset(4, 4, 16, 45, "const cert = forge.pki.createCertificate();",
				"javascript.node-forge.certificate.x509.create-certificate",
				map[string]string{"assetType": "certificate", "api": "node-forge.pki.createCertificate"}),
			want: map[string]string{
				"node-forge.Certificate.setSubject": "config",
				"node-forge.Certificate.setIssuer":  "config",
				"node-forge.Certificate.sign":       "operation",
			},
		},
		{
			name: "ca store created bare and filled",
			file: "cert.js",
			src:  nodeForgeSelfSigned,
			asset: cAsset(12, 12, 19, 45, "const caStore = forge.pki.createCaStore();",
				"javascript.node-forge.certificate.x509.create-ca-store",
				map[string]string{"assetType": "certificate", "api": "node-forge.pki.createCaStore"}),
			want: map[string]string{
				"node-forge.CaStore.addCertificate": "config",
			},
		},
		{
			name: "certification request on a binding with another name",
			file: "csr.js",
			src:  nodeForgeCSR,
			asset: cAsset(4, 4, 15, 50, "const csr = nf.pki.createCertificationRequest();",
				"javascript.node-forge.certificate.x509.create-certification-request",
				map[string]string{"assetType": "certificate", "api": "node-forge.pki.createCertificationRequest"}),
			want: map[string]string{
				"node-forge.CertificationRequest.setSubject":    "config",
				"node-forge.CertificationRequest.setAttributes": "config",
				"node-forge.CertificationRequest.sign":          "operation",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertNodeSupportingRoles(t, tc.file, tc.src, tc.asset, tc.want)
		})
	}
}
