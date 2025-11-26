package com.example.securesms.crypto.asymmetric

import AuthKeyPair
import AuthPrivateKey
import AuthPublicKey
import AuthenticationProvider
import android.os.Build
import androidx.annotation.RequiresApi
import com.example.securesms.crypto.hash.SHA256
import com.example.securesms.crypto.utils.MathUtils
import java.math.BigInteger
import java.security.SecureRandom
import com.example.securesms.crypto.models.RSAPrivateKey
import com.example.securesms.crypto.models.RSAPublicKey
import com.example.securesms.crypto.models.RSAKeyPair

/**
 * RSA Implementation based on cryptography fundamentals
 *
 * Key Setup:
 * 1. Choose two distinct large primes p and q
 * 2. Compute n = p × q (modulus)
 * 3. Compute φ(n) = (p-1)(q-1) (Euler's totient)
 * 4. Choose e with gcd(e, φ(n)) = 1 (public exponent)
 * 5. Compute d = e^-1 mod φ(n) (private exponent)
 *
 * Public Key: (e, n)
 * Private Key: (d, n)
 *
 * Encryption: C = M^e mod n
 * Decryption: M = C^d mod n
 */
class RSA {

    companion object {
        // Common public exponent
        private val DEFAULT_PUBLIC_EXPONENT = BigInteger.valueOf(65537) // 2^16 + 1

        /**
         * Generate RSA key pair with specified bit length
         * @param bitLength Key size in bits (e.g., 1024, 2048, 4096)
         * @return Pair of (publicKey, privateKey)
         */
        fun generateKeyPair(bitLength: Int = 2048): RSAKeyPair {
            val random = SecureRandom()

            // Generate two distinct primes
            val p = BigInteger.probablePrime(bitLength / 2, random)
            var q = BigInteger.probablePrime(bitLength / 2, random)

            // Ensure p != q
            while (q == p) {
                q = BigInteger.probablePrime(bitLength / 2, random)
            }

            // Compute n = p * q
            val n = p * q

            // Compute φ(n) = (p-1)(q-1)
            val phi = MathUtils.eulerTotient(p, q)

            // Use standard public exponent
            val e = DEFAULT_PUBLIC_EXPONENT

            // Verify gcd(e, φ(n)) = 1
            require(MathUtils.gcd(e, phi) == BigInteger.ONE) {
                "Invalid public exponent: gcd(e, φ(n)) != 1"
            }

            // Compute private exponent d = e^-1 mod φ(n)
            val d = MathUtils.modularInverse(e, phi)


            // Create RSAKeyPair

            return RSAKeyPair(RSAPublicKey(e, n), RSAPrivateKey(d, n, p, q))

        }

        /**
         * Generate key pair from specific primes (for testing/educational purposes)
         */
        fun generateKeyPairFromPrimes(p: BigInteger, q: BigInteger): Pair<RSAPublicKey, RSAPrivateKey> {
            require(p.isProbablePrime(100)) { "p must be prime" }
            require(q.isProbablePrime(100)) { "q must be prime" }
            require(p != q) { "p and q must be distinct" }

            val n = p * q
            val phi = MathUtils.eulerTotient(p, q)
            val e = DEFAULT_PUBLIC_EXPONENT

            require(MathUtils.gcd(e, phi) == BigInteger.ONE) {
                "Invalid public exponent for these primes"
            }

            val d = MathUtils.modularInverse(e, phi)

            return Pair(
                RSAPublicKey(e, n),
                RSAPrivateKey(d, n, p, q)
            )
        }
    }

    /**
     * Encrypt a message with public key
     * C = M^e mod n
     */
    fun encrypt(message: BigInteger, publicKey: RSAPublicKey): BigInteger {
        require(message >= BigInteger.ZERO) { "Message must be non-negative" }
        require(message < publicKey.n) { "Message must be less than modulus n" }

        return MathUtils.modPow(message, publicKey.e, publicKey.n)
    }

    /**
     * Decrypt a ciphertext with private key
     * M = C^d mod n
     */
    fun decrypt(ciphertext: BigInteger, privateKey: RSAPrivateKey): BigInteger {
        require(ciphertext >= BigInteger.ZERO) { "Ciphertext must be non-negative" }
        require(ciphertext < privateKey.n) { "Ciphertext must be less than modulus n" }

        return MathUtils.modPow(ciphertext, privateKey.d, privateKey.n)
    }

    /**
     * Encrypt a string message
     * Converts string to bytes, then to BigInteger blocks
     */
    fun encryptString(message: String, publicKey: RSAPublicKey): List<BigInteger> {
        val bytes = message.toByteArray()
        val blockSize = (publicKey.n.bitLength() - 1) / 8 - 1 // Leave room for padding

        val blocks = mutableListOf<BigInteger>()
        var offset = 0

        while (offset < bytes.size) {
            val blockLength = minOf(blockSize, bytes.size - offset)
            val block = bytes.copyOfRange(offset, offset + blockLength)
            val blockValue = BigInteger(1, block) // Positive BigInteger from bytes

            blocks.add(encrypt(blockValue, publicKey))
            offset += blockLength
        }

        return blocks
    }

    /**
     * Decrypt blocks back to string
     */
    fun decryptString(cipherBlocks: List<BigInteger>, privateKey: RSAPrivateKey): String {
        val decryptedBytes = mutableListOf<Byte>()

        for (block in cipherBlocks) {
            val decryptedBlock = decrypt(block, privateKey)
            val blockBytes = decryptedBlock.toByteArray()

            // Remove leading zero byte if present (from BigInteger representation)
            val startIndex = if (blockBytes[0] == 0.toByte() && blockBytes.size > 1) 1 else 0
            decryptedBytes.addAll(blockBytes.slice(startIndex until blockBytes.size))
        }

        return String(decryptedBytes.toByteArray())
    }

    /**
     * Encrypt numeric message (for educational purposes, like in the notebook)
     */
    fun encryptNumber(message: Long, publicKey: RSAPublicKey): BigInteger {
        return encrypt(BigInteger.valueOf(message), publicKey)
    }

    /**
     * Decrypt to numeric message
     */
    @RequiresApi(Build.VERSION_CODES.S)
    fun decryptNumber(ciphertext: BigInteger, privateKey: RSAPrivateKey): Long {
        return decrypt(ciphertext, privateKey).longValueExact()
    }
}

/**
 * RSA Authentication Provider
 *
 * Implements AuthenticationProvider interface for RSA-based authentication.
 * Supports multiple key sizes with different security levels.
 *
 * Usage:
 *   val provider = RSAAuthProvider(keySize = 2048)
 *   val keyPair = provider.generateKeyPair()
 *   val signature = provider.sign(data, privateKey)
 *   val valid = provider.verify(data, signature, publicKey)
 */
class RSAAuthProvider(
    override val keySize: Int = 2048
) : AuthenticationProvider {

    init {
        require(keySize in listOf(1024, 2048, 3072, 4096)) {
            "RSA key size must be 1024, 2048, 3072, or 4096 bits. Got: $keySize"
        }
    }

    override val algorithm = "RSA-$keySize"

    private val sha256 = SHA256()

    /**
     * Generate a new RSA key pair
     */
    override fun generateKeyPair(): AuthKeyPair {
        val keyPair = RSA.generateKeyPair(keySize)
        return AuthKeyPair.RSAAuth(keyPair)
    }

    /**
     * Sign data with RSA private key
     *
     * Process:
     * 1. Hash the data with SHA-256
     * 2. Convert hash to BigInteger
     * 3. Sign: signature = hash^d mod n (encrypt with private key)
     */
    override fun sign(data: ByteArray, privateKey: AuthPrivateKey): ByteArray {
        require(privateKey is AuthPrivateKey.RSAAuth) {
            "Expected RSA private key, got ${privateKey::class.simpleName}"
        }

        // Hash the data
        val hash = sha256.hash(data)
        val hashInt = BigInteger(1, hash)

        // Sign: signature = hash^d mod n
        val signature = MathUtils.modPow(hashInt, privateKey.key.d, privateKey.key.n)

        return signature.toByteArray()
    }

    /**
     * Verify RSA signature
     *
     * Process:
     * 1. Hash the data with SHA-256
     * 2. Decrypt signature: decrypted = signature^e mod n (decrypt with public key)
     * 3. Compare decrypted hash with computed hash
     */
    override fun verify(data: ByteArray, signature: ByteArray, publicKey: AuthPublicKey): Boolean {
        require(publicKey is AuthPublicKey.RSAAuth) {
            "Expected RSA public key, got ${publicKey::class.simpleName}"
        }

        return try {
            // Hash the data
            val hash = sha256.hash(data)
            val expectedHash = BigInteger(1, hash)

            // Decrypt signature: decrypted = signature^e mod n
            val signatureInt = BigInteger(1, signature)
            val decryptedHash = MathUtils.modPow(signatureInt, publicKey.key.e, publicKey.key.n)

            // Compare hashes
            decryptedHash == expectedHash

        } catch (e: Exception) {
            false
        }
    }

    /**
     * Get public key size in bytes
     * RSA public key consists of (e, n)
     * Size is primarily determined by modulus n
     */
    override fun getPublicKeySize(): Int {
        // Modulus n takes keySize/8 bytes
        // Public exponent e is typically small (3 bytes for 65537)
        return (keySize / 8) + 4
    }

    /**
     * Get signature size in bytes
     * RSA signature is the same size as the modulus
     */
    override fun getSignatureSize(): Int {
        return keySize / 8
    }

    /**
     * Get security level in bits
     */
    fun getSecurityBits(): Int {
        return when (keySize) {
            1024 -> 80
            2048 -> 112
            3072 -> 128
            4096 -> 152
            else -> 0
        }
    }
}
