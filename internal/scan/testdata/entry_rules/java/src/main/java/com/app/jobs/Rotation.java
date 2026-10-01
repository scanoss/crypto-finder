package com.app.jobs;

import java.security.MessageDigest;
import org.springframework.scheduling.annotation.*;

public class Rotation {
    // Scheduled through an on-demand import.
    @Scheduled(fixedRate = 60000)
    void rotate() throws Exception {
        MessageDigest.getInstance("SHA-384").digest(new byte[0]);
    }

    // A listener annotation written fully qualified.
    @org.springframework.kafka.annotation.KafkaListener(topics = "keys")
    void onKey(String key) throws Exception {
        MessageDigest.getInstance("SHA-224").digest(key.getBytes());
    }
}
