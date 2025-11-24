package com.example.securesms.crypto.symmetric

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom

/**
 * AES-GCM Encryption
 * Provides authenticated encryption with associated data
 */
class AES {

    companion object {
        private const val ALGORITHM = "AES/GCM/NoPadding"
        private const val TAG_LENGTH_BIT = 128
        private const val IV_LENGTH_BYTE = 12
    }

    private val random = SecureRandom()

    /**
     * Encrypt a string with AES-GCM
     * @param plaintext String to encrypt
     * @param key SecretKeySpec with AES key
     * @return Encrypted bytes (IV + ciphertext + tag)
     */
    fun encryptString(plaintext: String, key: SecretKeySpec): ByteArray {
        return encrypt(plaintext.toByteArray(), key)
    }

    /**
     * Encrypt bytes with AES-GCM
     * @param plaintext Bytes to encrypt
     * @param key SecretKeySpec with AES key
     * @return Encrypted bytes (IV + ciphertext + tag)
     */
    fun encrypt(plaintext: ByteArray, key: SecretKeySpec): ByteArray {
        // Generate random IV
        val iv = ByteArray(IV_LENGTH_BYTE)
        random.nextBytes(iv)

        // Create cipher
        val cipher = Cipher.getInstance(ALGORITHM)
        val gcmSpec = GCMParameterSpec(TAG_LENGTH_BIT, iv)
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)

        // Encrypt
        val ciphertext = cipher.doFinal(plaintext)

        // Return IV + ciphertext (GCM tag is included in ciphertext)
        return iv + ciphertext
    }

    /**
     * Decrypt AES-GCM encrypted bytes to string
     * @param encrypted Encrypted bytes (IV + ciphertext + tag)
     * @param key SecretKeySpec with AES key
     * @return Decrypted string
     */
    fun decryptString(encrypted: ByteArray, key: SecretKeySpec): String {
        return String(decrypt(encrypted, key))
    }

    /**
     * Decrypt AES-GCM encrypted bytes
     * @param encrypted Encrypted bytes (IV + ciphertext + tag)
     * @param key SecretKeySpec with AES key
     * @return Decrypted bytes
     */
    fun decrypt(encrypted: ByteArray, key: SecretKeySpec): ByteArray {
        // Extract IV and ciphertext
        val iv = encrypted.copyOfRange(0, IV_LENGTH_BYTE)
        val ciphertext = encrypted.copyOfRange(IV_LENGTH_BYTE, encrypted.size)

        // Create cipher
        val cipher = Cipher.getInstance(ALGORITHM)
        val gcmSpec = GCMParameterSpec(TAG_LENGTH_BIT, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec)

        // Decrypt and verify
        return cipher.doFinal(ciphertext)
    }
}