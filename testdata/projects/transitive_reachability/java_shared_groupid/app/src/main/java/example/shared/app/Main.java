package example.shared.app;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import example.shared.liba.Facade;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        byte[] data = "payload".getBytes();
        System.out.println(fingerprint(data).length);
        System.out.println(Facade.used(data).length);
    }

    static byte[] fingerprint(byte[] data) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    static byte[] legacy(byte[] data) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("MD5").digest(data);
    }
}
