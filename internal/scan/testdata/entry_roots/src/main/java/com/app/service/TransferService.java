package com.app.service;

public class TransferService {
    private final IdempotencyKeyHasher hasher = new IdempotencyKeyHasher();

    public String submit(String key) {
        String first = hasher.hash(key);
        String second = hasher.hash(key + "-retry");
        return first + second;
    }
}
