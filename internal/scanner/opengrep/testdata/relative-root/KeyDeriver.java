package fixture;

import javax.crypto.spec.PBEKeySpec;

public class KeyDeriver {
    private final int derivedKeyBitLength;
    private final String name;

    private static int hashBitLength(int keyBitLength) {
        return keyBitLength + keyBitLength;
    }

    public KeyDeriver(int keyBitLength) {
        this(hashBitLength(keyBitLength), "default");
    }

    protected KeyDeriver(int hashBitLength, String name) {
        this.name = name;
        this.derivedKeyBitLength = hashBitLength / 2;
    }

    protected PBEKeySpec spec(char[] password, byte[] salt, int iterations) {
        return new PBEKeySpec(password, salt, iterations, derivedKeyBitLength);
    }
}
