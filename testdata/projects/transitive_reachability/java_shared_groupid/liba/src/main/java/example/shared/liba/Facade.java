package example.shared.liba;

import java.security.NoSuchAlgorithmException;

import example.shared.libb.Hashing;

/** Facade is a direct dependency with no hashing of its own. */
public final class Facade {
    private Facade() {
    }

    /** used is the path the application calls. */
    public static byte[] used(byte[] data) throws NoSuchAlgorithmException {
        return Hashing.usedHash(data);
    }

    /** unused is a path nothing in the application calls. */
    public static byte[] unused(byte[] data) throws NoSuchAlgorithmException {
        return Hashing.unusedHash(data);
    }
}
