package com.example.securesms.crypto.symmetric

import com.example.securesms.crypto.hash.SHA256
import com.example.securesms.crypto.models.SessionKeys
import java.nio.ByteBuffer

/**
 * Key Derivation Function for TLS-style key generation
 *
 * Based on your notes:
 * Pre-Master Secret → Master Secret → Session Keys
 *
 * Master Secret = KDF(Pre-Master, Random_A, Random_B)
 * Session Keys:
 * - Kc_encrypt  (Client to Server encryption key)
 * - Kc_mac      (Client to Server MAC key)
 * - Ks_encrypt  (Server to Client encryption key)
 * - Ks_mac      (Server to Client MAC key)
 */
class KeyDerivation {

    private val sha256 = SHA256()

    /**
     * Derive Master Secret from Pre-Master Secret
     *
     * TLS 1.2 style:
     * master_secret = PRF(pre_master_secret, "master secret",
     *                     ClientHello.random + ServerHello.random)
     */
    fun deriveMasterSecret(
        preMasterSecret: ByteArray,
        clientRandom: ByteArray,
        serverRandom: ByteArray
    ): ByteArray {
        val label = "master secret".toByteArray(Charsets.UTF_8)
        val seed = clientRandom + serverRandom

        return prf(preMasterSecret, label, seed, 48) // 48 bytes = 384 bits
    }

    /**
     * Derive Session Keys from Master Secret
     *
     * key_block = PRF(master_secret, "key expansion",
     *                 ServerHello.random + ClientHello.random)
     *
     * Then partition into:
     * - client_write_MAC_key[32 bytes]
     * - server_write_MAC_key[32 bytes]
     * - client_write_key[32 bytes]      (AES-256)
     * - server_write_key[32 bytes]      (AES-256)
     */
    fun deriveSessionKeys(
        masterSecret: ByteArray,
        clientRandom: ByteArray,
        serverRandom: ByteArray
    ): SessionKeys {
        val label = "key expansion".toByteArray(Charsets.UTF_8)
        val seed = serverRandom + clientRandom // Note: reversed order

        // Need 128 bytes total for all keys
        val keyBlock = prf(masterSecret, label, seed, 128)

        // Partition the key block
        var offset = 0

        val clientMacKey = keyBlock.sliceArray(offset until offset + 32)
        offset += 32

        val serverMacKey = keyBlock.sliceArray(offset until offset + 32)
        offset += 32

        val clientEncryptKey = keyBlock.sliceArray(offset until offset + 32)
        offset += 32

        val serverEncryptKey = keyBlock.sliceArray(offset until offset + 32)

        return SessionKeys(
            clientEncryptKey = clientEncryptKey,
            clientMacKey = clientMacKey,
            serverEncryptKey = serverEncryptKey,
            serverMacKey = serverMacKey
        )
    }

    /**
     * Pseudo-Random Function (PRF) using HMAC-SHA256
     *
     * TLS 1.2 PRF: PRF(secret, label, seed) = P_SHA256(secret, label + seed)
     */
    private fun prf(
        secret: ByteArray,
        label: ByteArray,
        seed: ByteArray,
        outputLength: Int
    ): ByteArray {
        val labelAndSeed = label + seed
        return pHash(secret, labelAndSeed, outputLength)
    }

    /**
     * P_hash function for PRF
     *
     * P_hash(secret, seed) = HMAC(secret, A(1) + seed) +
     *                        HMAC(secret, A(2) + seed) +
     *                        HMAC(secret, A(3) + seed) + ...
     *
     * Where:
     * A(0) = seed
     * A(i) = HMAC(secret, A(i-1))
     */
    private fun pHash(secret: ByteArray, seed: ByteArray, outputLength: Int): ByteArray {
        val hmac = com.example.securesms.crypto.hash.HMAC()
        val result = ByteArray(outputLength)
        var offset = 0

        var a = seed // A(0) = seed

        while (offset < outputLength) {
            // A(i) = HMAC(secret, A(i-1))
            a = hmac.compute(secret, a)

            // HMAC(secret, A(i) + seed)
            val hmacResult = hmac.compute(secret, a + seed)

            // Copy to result buffer
            val copyLength = minOf(hmacResult.size, outputLength - offset)
            System.arraycopy(hmacResult, 0, result, offset, copyLength)
            offset += copyLength
        }

        return result
    }
}