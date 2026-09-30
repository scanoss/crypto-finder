package com.app.boot;

import jakarta.annotation.PostConstruct;
import java.security.MessageDigest;

public class KeyWarmup {
    @PostConstruct
    void warmUp() throws Exception {
        MessageDigest.getInstance("SHA-256").digest(new byte[0]);
    }
}
