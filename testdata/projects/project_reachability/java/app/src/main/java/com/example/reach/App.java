package com.example.reach;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.digest.DigestUtils;

public class App {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        byte[] data = "payload".getBytes();
        System.out.println(fingerprint(data).length);
        System.out.println(DigestUtils.sha256Hex(data));
    }

    static byte[] fingerprint(byte[] data) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    static byte[] legacy(byte[] data) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("MD5").digest(data);
    }
}
