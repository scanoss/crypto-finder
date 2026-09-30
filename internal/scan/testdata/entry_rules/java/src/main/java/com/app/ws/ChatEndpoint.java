package com.app.ws;

import jakarta.websocket.OnMessage;
import java.security.MessageDigest;

public class ChatEndpoint {
    @OnMessage
    public String onMessage(String message) throws Exception {
        return new String(MessageDigest.getInstance("MD5").digest(message.getBytes()));
    }
}
