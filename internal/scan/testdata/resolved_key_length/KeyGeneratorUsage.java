package issue272;

import javax.crypto.KeyGenerator;
import java.security.spec.AlgorithmParameterSpec;

class KeyGeneratorUsage {
    void literal() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
    }

    void unresolved(int keyBits) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(keyBits);
    }

    void nonInt(AlgorithmParameterSpec parameters) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(parameters);
    }
}
