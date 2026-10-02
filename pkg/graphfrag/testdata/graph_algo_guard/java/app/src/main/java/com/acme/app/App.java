package com.acme.app;

import com.acme.dep.Digester;
import com.acme.dep.Sha256Digester;
import java.nio.charset.StandardCharsets;

public class App {
    private final Digester digester;

    public App(Digester digester) {
        this.digester = digester;
    }

    public byte[] fingerprint(String text) throws Exception {
        return digester.digest(text.getBytes(StandardCharsets.UTF_8));
    }

    public static void main(String[] args) throws Exception {
        App app = new App(new Sha256Digester());
        System.out.println(app.fingerprint("hello").length);
        Digester inline = data -> data;
        new App(inline).fingerprint("x");
    }
}
