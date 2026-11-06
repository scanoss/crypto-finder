package com.app.admin;

import com.app.service.TransferService;

@AdminCommand
public class ReplayTool {
    public void replay(String key) {
        new TransferService().submit(key);
    }
}
