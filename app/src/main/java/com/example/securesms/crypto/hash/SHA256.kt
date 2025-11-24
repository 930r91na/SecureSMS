package com.example.securesms.crypto.hash

import java.security.MessageDigest

/**
 * SHA-256 Hash Function
 * Based on your notes: produces 256-bit (32-byte) digest
 */
class SHA256 {

    private val digest = MessageDigest.getInstance("SHA-256")

    /**
     * Hash a byte array
     */
    fun hash(data: ByteArray): ByteArray {
        return digest.digest(data)
    }

    /**
     * Hash a string
     */
    fun hash(text: String): ByteArray {
        return hash(text.toByteArray(Charsets.UTF_8))
    }

    /**
     * Hash multiple inputs (useful for handshake verification)
     */
    fun hash(vararg data: ByteArray): ByteArray {
        val combined = data.fold(ByteArray(0)) { acc, bytes -> acc + bytes }
        return hash(combined)
    }

    /**
     * Hash to hex string
     */
    fun hashToHex(data: ByteArray): String {
        return hash(data).toHex()
    }

    private fun ByteArray.toHex(): String {
        return joinToString("") { "%02x".format(it) }
    }
}