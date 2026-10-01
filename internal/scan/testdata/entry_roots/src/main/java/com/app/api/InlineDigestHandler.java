package com.app.api;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.security.MessageDigest;

public final class InlineDigestHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.digest(exchange.getRequestURI().toString().getBytes());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
