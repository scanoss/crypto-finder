package com.example.ledger;

public class Application {
    public static void main(String[] args) throws Exception {
        System.out.println(new LedgerController().postEntry("entry"));
    }
}
