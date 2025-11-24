package com.example.securesms.crypto.hash

import java.security.MessageDigest

/**
 * SHA-256 Hash Function Implementation
 *
 * SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function
 * that produces a 256-bit (32-byte) hash value.
 *
 * Properties:
 * - Input: Any length message
 * - Output: Fixed 256-bit (32-byte) digest
 * - One-way: Cannot reverse the hash
 * - Collision-resistant: Hard to find two messages with same hash
 * - Avalanche effect: Small input change → large output change
 *
 * Used for:
 * - Data integrity verification
 * - Digital signatures
 * - Key derivation
 * - HMAC authentication
 */
class SHA256 {

    /**
     * Compute SHA-256 hash of data
     * @param data Input data to hash
     * @return 32-byte hash digest
     */
    fun hash(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }

    /**
     * Compute SHA-256 hash of string
     * @param message Input string to hash
     * @return 32-byte hash digest
     */
    fun hash(message: String): ByteArray {
        return hash(message.toByteArray(Charsets.UTF_8))
    }

    /**
     * Compute SHA-256 hash of multiple inputs concatenated
     * @param inputs Variable number of byte arrays to hash
     * @return 32-byte hash digest
     */
    fun hash(vararg inputs: ByteArray): ByteArray {
        val combined = inputs.fold(ByteArray(0)) { acc, bytes -> acc + bytes }
        return hash(combined)
    }

    /**
     * Compute SHA-256 hash and return as hex string
     * @param data Input data to hash
     * @return Hex string representation of hash
     */
    fun hashToHex(data: ByteArray): String {
        return hash(data).joinToString("") { "%02x".format(it) }
    }

    /**
     * Compute SHA-256 hash of string and return as hex string
     * @param message Input string to hash
     * @return Hex string representation of hash
     */
    fun hashToHex(message: String): String {
        return hashToHex(message.toByteArray(Charsets.UTF_8))
    }

    /**
     * Verify that data matches expected hash
     * @param data Data to verify
     * @param expectedHash Expected hash value
     * @return true if hashes match, false otherwise
     */
    fun verify(data: ByteArray, expectedHash: ByteArray): Boolean {
        val computedHash = hash(data)
        return computedHash.contentEquals(expectedHash)
    }

    /**
     * Verify that string matches expected hash
     * @param message Message to verify
     * @param expectedHashHex Expected hash as hex string
     * @return true if hashes match, false otherwise
     */
    fun verify(message: String, expectedHashHex: String): Boolean {
        val computedHash = hashToHex(message)
        return computedHash.equals(expectedHashHex, ignoreCase = true)
    }
}