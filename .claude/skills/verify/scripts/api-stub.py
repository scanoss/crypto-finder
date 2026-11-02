#!/usr/bin/env python3
"""Local stand-in for the SCANOSS component findings endpoint, for the cbom
drive only. It listens on 127.0.0.1 (an OS-chosen port, written to PORT_FILE),
answers POST /v3/cryptography/reachability/component with synthetic findings
(the same shape internal/cli/cbom_test.go serves), and logs every request as a
JSON line to LOG_FILE. It holds no real rules or mined data.

Usage: api-stub.py PORT_FILE LOG_FILE
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

ENDPOINT = "/v3/cryptography/reachability/component"

# purl base -> response body. Anything else is not mined.
ANSWERS = {
    "pkg:npm/node-forge": {
        "rules_version": "verify-stub",
        "info_code": "READY",
        "data": [{
            "version": "1.3.1",
            "findings": [{
                "file_path": "lib/aes.js",
                "language": "javascript",
                "cryptographic_assets": [{
                    "start_line": 3,
                    "end_line": 3,
                    "match": "forge.cipher.createCipher('AES-CBC', key)",
                    "metadata": {"assetType": "algorithm", "algorithmName": "AES",
                                 "algorithmFamily": "AES", "algorithmPrimitive": "block-cipher"},
                    "rules": [{"id": "verify-stub.aes"}],
                }],
            }],
        }],
    },
    "pkg:npm/left-pad": {
        "rules_version": "verify-stub",
        "info_code": "READY",
        "data": [{"version": "1.3.0", "findings": []}],
    },
}
NOT_MINED = {"info_code": "COMPONENT_NOT_FOUND", "data": []}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        with open(LOG_FILE, "a", encoding="utf-8") as log:
            log.write(json.dumps({"method": "POST", "path": self.path, "purl": body.get("purl"),
                                  "requirement": body.get("requirement"),
                                  "api_key_header": any(h.lower() == "x-api-key" for h in self.headers)}) + "\n")
        if self.path != ENDPOINT:
            self.send_response(404)
            self.end_headers()
            return
        purl = (body.get("purl") or "").split("@")[0]
        payload = json.dumps(ANSWERS.get(purl, NOT_MINED)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    PORT_FILE, LOG_FILE = sys.argv[1], sys.argv[2]
    server = HTTPServer(("127.0.0.1", 0), Handler)
    with open(PORT_FILE, "w", encoding="utf-8") as f:
        f.write(str(server.server_address[1]))
    server.serve_forever()
