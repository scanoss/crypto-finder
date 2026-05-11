package com.testapp;

import com.testapp.service.CryptoService;

public class Main {
    public static void main(String[] args) throws Exception {
        CryptoService service = new CryptoService();
        byte[] encrypted = service.encrypt("Hello, World!".getBytes());
        System.out.println("Encrypted " + encrypted.length + " bytes");
    }
}
