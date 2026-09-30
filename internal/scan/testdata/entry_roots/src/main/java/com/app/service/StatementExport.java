package com.app.service;

import javax.crypto.Cipher;

public class StatementExport {
    public byte[] encryptForArchive(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        return cipher.doFinal(data);
    }
}
