package com.acme.dep;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Sha256Digester implements Digester {
    @Override
    public byte[] digest(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(data);
        return md.digest();
    }

    public byte[] seal(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return cipher.doFinal(digest(data));
    }
}
