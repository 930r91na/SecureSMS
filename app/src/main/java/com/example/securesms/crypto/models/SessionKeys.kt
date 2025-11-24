package com.example.securesms.crypto.models

data class SessionKeys(
    val clientEncryptKey: ByteArray,  // Kc for encryption
    val clientMacKey: ByteArray,      // MACc for authentication
    val serverEncryptKey: ByteArray,  // Ks for encryption
    val serverMacKey: ByteArray       // MACs for authentication
) {
    override fun toString(): String {
        return """
            SessionKeys(
              Client Encrypt: ${clientEncryptKey.toHex().take(16)}...
              Client MAC:     ${clientMacKey.toHex().take(16)}...
              Server Encrypt: ${serverEncryptKey.toHex().take(16)}...
              Server MAC:     ${serverMacKey.toHex().take(16)}...
            )
        """.trimIndent()
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
}

data class MasterSecret(
    val value: ByteArray,
    val clientRandom: ByteArray,
    val serverRandom: ByteArray
)