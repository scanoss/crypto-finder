package com.acme.dep;

public final class Digesters {
    private Digesters() {
    }

    public static Digester sha256() {
        return new Sha256Digester();
    }
}
