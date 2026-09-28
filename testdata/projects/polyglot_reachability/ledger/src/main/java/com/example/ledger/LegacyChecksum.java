package com.example.ledger;

import java.security.MessageDigest;

public class LegacyChecksum {
    static byte[] checksum(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);
    }
}
