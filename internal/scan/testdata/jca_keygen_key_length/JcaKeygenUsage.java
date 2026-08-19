package issue273;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

class JcaKeygenUsage {
    void keyPairGeneratorLiteral() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        generator.generateKeyPair();
    }

    void keyPairGeneratorWithRandom(SecureRandom random) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072, random);
        generator.generateKeyPair();
    }

    void rsaKeyGenParameterSpec() throws Exception {
        RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(spec);
        generator.generateKeyPair();
    }

    void ecGenParameterSpec() throws Exception {
        ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(spec);
        generator.generateKeyPair();
    }

    void secretKeySpecLiteral() throws Exception {
        SecretKeySpec key = new SecretKeySpec(new byte[32], "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipher.doFinal(new byte[0]);
    }

    void secretKeySpecUnresolved(byte[] material) throws Exception {
        SecretKeySpec key = new SecretKeySpec(material, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipher.doFinal(new byte[0]);
    }

    void keyPairGeneratorUnresolved(int keyBits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keyBits);
        generator.generateKeyPair();
    }
}
