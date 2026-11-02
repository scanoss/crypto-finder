package example.translibb;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Hashing is a transitive dependency that does the hashing. */
public final class Hashing {
    private Hashing() {
    }

    /** usedHash is reached from the application through Facade.used. */
    public static byte[] usedHash(byte[] data) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    /** unusedHash is reached only from Facade.unused. */
    public static byte[] unusedHash(byte[] data) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-512").digest(data);
    }
}
