package com.app.boot;

import java.security.MessageDigest;
import org.acme.lifecycle.PostConstruct;

public class LocalHooks {
    // @PostConstruct from a package no container reads: not an entry point.
    @PostConstruct
    void prime() throws Exception {
        MessageDigest.getInstance("SHA-512").digest(new byte[0]);
    }
}
