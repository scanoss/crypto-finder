package com.example.keys;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

// Each helper creates a KeyPairGenerator in one method and has its size or
// curve fixed in another. The synthetic rule sees only the getInstance call.
public class Keys {
    private static final int CONSTANT_BITS = 3072;

    // A: the size is a literal next to getInstance.
    static KeyPair genFromName(String alg) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg);
        kpg.initialize(3072);
        return kpg.generateKeyPair();
    }

    // B: the size arrives as a parameter; both callers pass 4096.
    static KeyPair genFromNameAndSize(String alg, int size) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg);
        kpg.initialize(size);
        return kpg.generateKeyPair();
    }

    // C: the generator is returned; the caller sets the size.
    static KeyPairGenerator newKpg() throws Exception {
        return KeyPairGenerator.getInstance("RSA");
    }

    // D: two callers pass different sizes.
    static KeyPair genDisagree(int size) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(size);
        return kpg.generateKeyPair();
    }

    // E: the only caller passes a static final constant.
    static KeyPair genFromConstant(int size) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(size);
        return kpg.generateKeyPair();
    }

    // F: the curve name arrives as a parameter.
    static KeyPair genCurve(String curve) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    public static void main(String[] args) throws Exception {
        genFromName("RSA");
        genFromNameAndSize("RSA", 4096);

        KeyPairGenerator kpg = newKpg();
        kpg.initialize(2048);
        kpg.generateKeyPair();

        genDisagree(2048);
        genDisagree(4096);
        genFromConstant(CONSTANT_BITS);
        genCurve("secp384r1");
    }

    static KeyPair renew() throws Exception {
        return genFromNameAndSize("RSA", 4096);
    }
}
