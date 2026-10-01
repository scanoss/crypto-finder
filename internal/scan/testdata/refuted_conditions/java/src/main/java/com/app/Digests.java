package com.app;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class Digests {
    static byte[] hashWith(String alg, byte[] data) throws Exception {
        return MessageDigest.getInstance(alg).digest(data);
    }

    static byte[] hashOther(String algorithm, byte[] data) throws Exception {
        return MessageDigest.getInstance(algorithm).digest(data);
    }

    static byte[] legacyTag(byte[] value) throws Exception {
        return hashOther("SHA-1", value);
    }

    static byte[] currentTag(byte[] value) throws Exception {
        return hashOther("SHA-256", value);
    }

    public static void main(String[] args) throws Exception {
        hashWith("SHA-1", args[0].getBytes(StandardCharsets.UTF_8));
        hashWith("SHA-256", args[1].getBytes(StandardCharsets.UTF_8));
        legacyTag(args[2].getBytes(StandardCharsets.UTF_8));
        currentTag(args[3].getBytes(StandardCharsets.UTF_8));
    }
}
