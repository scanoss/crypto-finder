package com.app.ws;

import java.security.MessageDigest;

public class AuditFeed {
    // Not an entry point, and nothing calls it.
    public byte[] fingerprint(String line) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(line.getBytes());
    }
}
