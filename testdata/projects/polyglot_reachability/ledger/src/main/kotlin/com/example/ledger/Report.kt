package com.example.ledger

import java.security.MessageDigest

fun reportDigest(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-1").digest(data)
