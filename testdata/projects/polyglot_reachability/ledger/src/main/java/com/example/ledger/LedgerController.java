package com.example.ledger;

public class LedgerController {
    private final DigestService digests = new DigestService();

    public String postEntry(String body) throws Exception {
        return digests.fingerprint(body);
    }
}
