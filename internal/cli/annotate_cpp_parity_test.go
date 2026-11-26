//go:build !windows

// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli

import (
	"encoding/json"
	"testing"
)

const annotateCPPRules = `rules:
- id: acme-qhash
  languages: [cpp]
  message: SHA-256 hash
  severity: INFO
  pattern: QCryptographicHash $H(QCryptographicHash::Sha256);
  metadata:
    crypto:
      assetType: algorithm
      algorithmPrimitive: hash
- id: acme-server
  languages: [cpp]
  message: TLS server
  severity: INFO
  pattern: std::make_unique<acme::Server>(...)
  metadata:
    crypto:
      assetType: protocol
- id: acme-keygen
  languages: [cpp]
  message: Private key generation
  severity: INFO
  pattern: $K.GenPrivKey()
  metadata:
    crypto:
      assetType: related-crypto-material
`

// A C rule a C++ scan matches too.
const annotateCPPCRules = `rules:
- id: acme-include
  languages: [c, cpp]
  message: OpenSSL EVP include
  severity: INFO
  pattern-regex: '#include\s+<openssl/evp\.h>'
  metadata:
    crypto:
      assetType: related-crypto-material
`

// The project declares QCryptographicHash, a type the C++ KB describes, and
// defines only its constructor and reset(): addData and result are calls of
// the project's own type, which take no KB category.
var annotateCPPFiles = map[string]string{
	"lib/qhash.h": `#pragma once
class QByteArray {};
class QCryptographicHash {
public:
    enum Algorithm { Sha256 };
    explicit QCryptographicHash(Algorithm method);
    void reset();
    void addData(const QByteArray &data);
    QByteArray result() const;
};
`,
	"lib/qhash.cpp": `#include "qhash.h"
QCryptographicHash::QCryptographicHash(Algorithm method) {}
void QCryptographicHash::reset() {}
`,
	"app/server.h": `#pragma once
namespace acme {
class Request {
public:
    int arg_count() const;
};
class Server {
public:
    Server(int port, const char *cipher);
};
}
`,
	// make_unique<acme::Server> is a call of make_unique and a construction
	// of acme::Server at one span, neither resolved to a definition.
	"app/server.cpp": `#include "server.h"
#include "../lib/qhash.h"
#include <memory>
namespace acme {
int Request::arg_count() const { return 1; }
}
QByteArray digest(const acme::Request &req, const QByteArray &data) {
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.reset();
    if (req.arg_count() > 0)
        hash.addData(data);
    return hash.result();
}
std::unique_ptr<acme::Server> serve(int port) {
    auto server = std::make_unique<acme::Server>(port, "AES256-GCM");
    return server;
}
`,
	// PrivKey overrides PubKey::writeToJSON, so pk.writeToJSON() also
	// dispatches to PrivKey's, which sk.writeToJSON() calls directly on
	// another line at the same columns.
	"app/keys.h": `#pragma once
namespace acme {
class Json {
public:
    const char *pretty(long width = 2) const;
};
class PubKey {
public:
    virtual ~PubKey();
    virtual Json writeToJSON() const;
};
class PrivKey : public PubKey {
public:
    void GenPrivKey();
    Json writeToJSON() const override;
};
}
`,
	"app/keys.cpp": `#include "keys.h"
namespace acme {
const char *Json::pretty(long width) const { return ""; }
PubKey::~PubKey() {}
Json PubKey::writeToJSON() const { return Json(); }
void PrivKey::GenPrivKey() {}
Json PrivKey::writeToJSON() const { return Json(); }
}
`,
	"app/main.cpp": `#include "keys.h"
#include <iostream>
int main() {
    acme::PrivKey sk;
    sk.GenPrivKey();
    std::cout << sk.writeToJSON().pretty() << std::endl;
    const acme::PubKey& pk = sk;
    std::cout << pk.writeToJSON().pretty() << std::endl;
    return 0;
}
`,
	// A C parse of the header reads the namespace as a function that holds
	// the include; the C++ graph the fragment stores has no function there.
	"tls/tls.h": `#pragma once
namespace acme {
#include <openssl/evp.h>
}
`,
	"tls/util.c": "int util(void) { return 0; }\n",
}

// annotate of a stored C++ graph, without the source, writes the findings and
// the crypto sections the scan that stored it wrote: a finding of a C rule in
// a header keeps the occurrence key of the C++ graph; a supporting call keeps
// the callee as written when the graph resolved it to a project function, and
// no KB category when its type is the project's own; make_unique<T> reports
// T's construction; and a call through a base reference stays out of the
// lifecycle of the object a dispatch edge of it names.
func TestAnnotateCPPWritesTheScanCryptoSections(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a compiled CLI")
	}
	sections := annotateCFamilyRoundTrip(t, "cpp", map[string]string{"cpp": annotateCPPRules, "c": annotateCPPCRules}, annotateCPPFiles,
		"cpp.x.acme-qhash", "cpp.x.acme-server", "cpp.x.acme-keygen", "c.x.acme-include")

	var supporting []struct {
		Category         string `json:"category"`
		MatchedOperation struct {
			Expression string `json:"expression"`
		} `json:"matched_operation"`
	}
	if err := json.Unmarshal(sections["supporting_calls"], &supporting); err != nil {
		t.Fatal(err)
	}
	categories := map[string]string{}
	for _, call := range supporting {
		categories[call.MatchedOperation.Expression] = call.Category
	}
	for _, expression := range []string{"hash.reset", "hash.addData", "hash.result", "sk.writeToJSON"} {
		if category, ok := categories[expression]; !ok || category != "" {
			t.Errorf("supporting calls by expression = %v, want %s with no category", categories, expression)
		}
	}
	if _, ok := categories["pk.writeToJSON"]; ok {
		t.Errorf("supporting calls by expression = %v, want no pk.writeToJSON", categories)
	}

	var operations []struct {
		RuleID     string `json:"rule_id"`
		CryptoCall struct {
			FunctionName string `json:"function_name"`
		} `json:"crypto_call"`
	}
	if err := json.Unmarshal(sections["crypto_annotations"], &operations); err != nil {
		t.Fatal(err)
	}
	for _, op := range operations {
		if op.RuleID == "cpp.x.acme-server" && op.CryptoCall.FunctionName != "app.acme::Server.Server" {
			t.Errorf("make_unique crypto call = %q, want the construction app.acme::Server.Server", op.CryptoCall.FunctionName)
		}
	}
}
