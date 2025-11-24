package com.example.securesms.crypto.symmetric

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES (Advanced Encryption Standard) Implementation
 *
 * AES is a symmetric block cipher that operates on 128-bit blocks.
 *
 * Key Sizes:
 * - AES-128: 128-bit key (16 bytes) - 10 rounds
 * - AES-192: 192-bit key (24 bytes) - 12 rounds
 * - AES-256: 256-bit key (32 bytes) - 14 rounds
 *
 * Mode: GCM (Galois/Counter Mode)
 * - Provides both encryption and authentication
 * - No padding needed (stream cipher mode)
 * - Includes authentication tag for integrity
 *
 * Structure:
 * - Plaintext → AES-GCM → Ciphertext + Authentication Tag
 * - Ciphertext + Tag → AES-GCM → Plaintext (or fail if tampered)
 */
class AES {

    companion object {
        private const val ALGORITHM = "AES"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH = 128 // bits
        private const val GCM_IV_LENGTH = 12 // bytes (96 bits recommended for GCM)

        const val KEY_SIZE_128 = 128
        const val KEY_SIZE_192 = 192
        const val KEY_SIZE_256 = 256

        /**
         * Generate a new random AES key
         * @param keySize Key size in bits (128, 192, or 256)
         * @return Generated secret key
         */
        fun generateKey(keySize: Int = KEY_SIZE_256): SecretKey {
            require(keySize in listOf(KEY_SIZE_128, KEY_SIZE_192, KEY_SIZE_256)) {
                "Key size must be 128, 192, or 256 bits"
            }

            val keyGen = KeyGenerator.getInstance(ALGORITHM)
            keyGen.init(keySize)
            return keyGen.generateKey()
        }

        /**
         * Create SecretKey from byte array
         * @param keyBytes Key material
         * @return SecretKey object
         */
        fun keyFromBytes(keyBytes: ByteArray): SecretKey {
            require(keyBytes.size in listOf(16, 24, 32)) {
                "Key must be 16, 24, or 32 bytes (128, 192, or 256 bits)"
            }
            return SecretKeySpec(keyBytes, ALGORITHM)
        }
    }

    private val random = SecureRandom()

    /**
     * Encrypted message containing ciphertext, IV, and authentication tag
     */
    data class EncryptedMessage(
        val ciphertext: ByteArray,
        val iv: ByteArray,
        val authTag: ByteArray
    ) {
        /**
         * Combine all components into single byte array for transmission
         * Format: [IV_LENGTH(1 byte)][IV][CIPHERTEXT+TAG]
         */
        fun toBytes(): ByteArray {
            return byteArrayOf(iv.size.toByte()) + iv + ciphertext
        }

        companion object {
            /**
             * Parse encrypted message from bytes
             */
            fun fromBytes(data: ByteArray): EncryptedMessage {
                require(data.isNotEmpty()) { "Empty data" }

                val ivLength = data[0].toInt()
                require(data.size > ivLength + 1) { "Invalid data format" }

                val iv = data.sliceArray(1 until 1 + ivLength)
                val ciphertext = data.sliceArray(1 + ivLength until data.size)

                // In GCM mode, the authentication tag is appended to ciphertext
                // We'll extract it during decryption
                return EncryptedMessage(ciphertext, iv, ByteArray(0))
            }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as EncryptedMessage
            if (!ciphertext.contentEquals(other.ciphertext)) return false
            if (!iv.contentEquals(other.iv)) return false
            if (!authTag.contentEquals(other.authTag)) return false
            return true
        }

        override fun hashCode(): Int {
            var result = ciphertext.contentHashCode()
            result = 31 * result + iv.contentHashCode()
            result = 31 * result + authTag.contentHashCode()
            return result
        }
    }

    /**
     * Encrypt data using AES-GCM
     * @param plaintext Data to encrypt
     * @param key Secret key
     * @return Encrypted message with IV and auth tag
     */
    fun encrypt(plaintext: ByteArray, key: SecretKey): EncryptedMessage {
        // Generate random IV for GCM
        val iv = ByteArray(GCM_IV_LENGTH)
        random.nextBytes(iv)

        // Initialize cipher
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)

        // Encrypt (GCM automatically appends authentication tag)
        val ciphertextWithTag = cipher.doFinal(plaintext)

        // Extract authentication tag (last 16 bytes)
        val tagLength = GCM_TAG_LENGTH / 8
        val ciphertext = ciphertextWithTag.sliceArray(0 until ciphertextWithTag.size - tagLength)
        val authTag = ciphertextWithTag.sliceArray(ciphertextWithTag.size - tagLength until ciphertextWithTag.size)

        return EncryptedMessage(ciphertextWithTag, iv, authTag)
    }

    /**
     * Encrypt string using AES-GCM
     * @param message String to encrypt
     * @param key Secret key
     * @return Encrypted message with IV and auth tag
     */
    fun encrypt(message: String, key: SecretKey): EncryptedMessage {
        return encrypt(message.toByteArray(Charsets.UTF_8), key)
    }

    /**
     * Decrypt data using AES-GCM
     * @param encrypted Encrypted message
     * @param key Secret key
     * @return Decrypted plaintext
     * @throws Exception if authentication fails or decryption fails
     */
    fun decrypt(encrypted: EncryptedMessage, key: SecretKey): ByteArray {
        // Initialize cipher
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, encrypted.iv)
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec)

        // Decrypt and verify (GCM automatically verifies authentication tag)
        return cipher.doFinal(encrypted.ciphertext)
    }

    /**
     * Decrypt data and return as string
     * @param encrypted Encrypted message
     * @param key Secret key
     * @return Decrypted string
     * @throws Exception if authentication fails or decryption fails
     */
    fun decryptToString(encrypted: EncryptedMessage, key: SecretKey): String {
        val plaintext = decrypt(encrypted, key)
        return String(plaintext, Charsets.UTF_8)
    }

    /**
     * Encrypt with optional Additional Authenticated Data (AAD)
     * AAD is authenticated but not encrypted
     * @param plaintext Data to encrypt
     * @param key Secret key
     * @param aad Additional authenticated data
     * @return Encrypted message
     */
    fun encryptWithAAD(plaintext: ByteArray, key: SecretKey, aad: ByteArray): EncryptedMessage {
        val iv = ByteArray(GCM_IV_LENGTH)
        random.nextBytes(iv)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)

        // Add AAD before encryption
        cipher.updateAAD(aad)

        val ciphertextWithTag = cipher.doFinal(plaintext)
        val tagLength = GCM_TAG_LENGTH / 8
        val authTag = ciphertextWithTag.sliceArray(ciphertextWithTag.size - tagLength until ciphertextWithTag.size)

        return EncryptedMessage(ciphertextWithTag, iv, authTag)
    }

    /**
     * Decrypt with Additional Authenticated Data (AAD)
     * @param encrypted Encrypted message
     * @param key Secret key
     * @param aad Additional authenticated data (must match encryption AAD)
     * @return Decrypted plaintext
     * @throws Exception if authentication fails
     */
    fun decryptWithAAD(encrypted: EncryptedMessage, key: SecretKey, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH, encrypted.iv)
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec)

        // Add AAD before decryption (must match encryption AAD)
        cipher.updateAAD(aad)

        return cipher.doFinal(encrypted.ciphertext)
    }
}