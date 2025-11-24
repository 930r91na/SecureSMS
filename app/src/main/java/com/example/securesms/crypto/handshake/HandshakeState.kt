package com.example.securesms.crypto.handshake

enum class HandshakeState {
    IDLE,
    CLIENT_HELLO_SENT,
    SERVER_HELLO_SENT,
    CLIENT_KEY_EXCHANGE_SENT,
    KEYS_DERIVED,
    FINISHED_SENT,
    ESTABLISHED
}