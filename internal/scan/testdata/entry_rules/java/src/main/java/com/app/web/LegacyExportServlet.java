package com.app.web;

import javax.crypto.Cipher;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LegacyExportServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        try {
            Cipher.getInstance("DES/ECB/PKCS5Padding");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
