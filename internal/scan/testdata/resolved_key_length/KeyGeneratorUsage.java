package issue272;

import javax.crypto.KeyGenerator;
import java.security.spec.AlgorithmParameterSpec;

class KeyGeneratorUsage {
    void literal() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        generator.generateKey();
    }

    void unresolved(int keyBits) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(keyBits);
        generator.generateKey();
    }

    void nonInt(AlgorithmParameterSpec parameters) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(parameters);
        generator.generateKey();
    }
}
