package com.app.util;

import java.security.MessageDigest;

public final class LegacyChecksum {
    private LegacyChecksum() {
    }

    @Deprecated
    public static String legacyChecksum(String contents) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            return new String(digest.digest(contents.getBytes()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
