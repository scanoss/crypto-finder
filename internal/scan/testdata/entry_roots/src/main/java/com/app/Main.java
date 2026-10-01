package com.app;

import com.app.api.InlineDigestHandler;
import com.app.api.TransferHandler;
import com.app.service.TransferService;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;

public final class Main {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/transfers", new TransferHandler(new TransferService()));
        server.createContext("/digest", new InlineDigestHandler());
        server.start();
    }
}
