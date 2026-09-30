package com.app.service;

import java.security.MessageDigest;

public class IdempotencyKeyHasher {
    public String hash(String key) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return new String(digest.digest(key.getBytes()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
