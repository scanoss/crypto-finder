package com.example.ledger;

import java.security.MessageDigest;
import java.util.HexFormat;

public class DigestService {
    public String fingerprint(String body) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body.getBytes()));
    }
}
