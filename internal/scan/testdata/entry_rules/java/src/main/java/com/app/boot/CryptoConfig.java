package com.app.boot;

import javax.crypto.KeyGenerator;
import org.springframework.context.annotation.Bean;

public class CryptoConfig {
    @Bean
    public KeyGenerator sessionKeys() throws Exception {
        return KeyGenerator.getInstance("AES");
    }
}
