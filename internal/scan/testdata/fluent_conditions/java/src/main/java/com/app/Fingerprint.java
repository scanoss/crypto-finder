package com.app;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class Fingerprint {
    static byte[] salted() throws Exception {
        return MessageDigest.getInstance("MD5").digest("acme".getBytes(StandardCharsets.UTF_8));
    }

    public static void main(String[] args) throws Exception {
        salted();
    }
}
