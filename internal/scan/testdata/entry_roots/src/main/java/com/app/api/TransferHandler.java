package com.app.api;

import com.app.service.TransferService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

public final class TransferHandler implements HttpHandler {
    private final TransferService service;

    public TransferHandler(TransferService service) {
        this.service = service;
    }

    @Override
    public void handle(HttpExchange exchange) {
        service.submit(exchange.getRequestURI().toString());
    }
}
