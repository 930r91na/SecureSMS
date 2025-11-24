package com.example.securesms.crypto.hash

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HMAC-SHA256 for Message Authentication
 * Based on your notes: HMAC = Hash(Key + Message)
 *
 * Provides:
 * - Data Integrity: detect any modification
 * - Authentication: verify sender has the key
 * - Non-repudiation: proof of message origin
 */
class HMAC {

    companion object {
        private const val ALGORITHM = "HmacSHA256"
    }

    /**
     * Compute HMAC-SHA256
     * @param key Secret key for HMAC
     * @param data Data to authenticate
     * @return 32-byte HMAC tag
     */
    fun compute(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(ALGORITHM)
        val secretKey = SecretKeySpec(key, ALGORITHM)
        mac.init(secretKey)
        return mac.doFinal(data)
    }

    /**
     * Compute HMAC for multiple inputs
     */
    fun compute(key: ByteArray, vararg data: ByteArray): ByteArray {
        val combined = data.fold(ByteArray(0)) { acc, bytes -> acc + bytes }
        return compute(key, combined)
    }

    /**
     * Verify HMAC (constant-time comparison)
     */
    fun verify(key: ByteArray, data: ByteArray, expectedHmac: ByteArray): Boolean {
        val computedHmac = compute(key, data)
        return computedHmac.contentEquals(expectedHmac)
    }

    /**
     * Verify HMAC for message structure
     */
    fun verifyMessage(key: ByteArray, message: ByteArray, receivedHmac: ByteArray): Boolean {
        return verify(key, message, receivedHmac)
    }
}