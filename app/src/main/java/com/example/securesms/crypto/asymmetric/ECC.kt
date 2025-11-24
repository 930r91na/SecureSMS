package com.example.securesms.crypto.asymmetric

import android.os.Build
import androidx.annotation.RequiresApi
import com.example.securesms.crypto.models.*
import com.example.securesms.crypto.utils.MathUtils
import java.math.BigInteger
import java.security.SecureRandom
import java.security.MessageDigest

/**
 * Elliptic Curve Cryptography (ECC) Implementation
 *
 * Elliptic Curve: y² = x³ + ax + b (mod p)
 *
 * Key Generation:
 * 1. Choose a standard curve (p, a, b, G, n)
 * 2. Generate private key: d ∈ [1, n-1]
 * 3. Compute public key: Q = d·G
 *
 * ECDH Key Exchange:
 * - Alice: private a, public A = a·G
 * - Bob: private b, public B = b·G
 * - Shared secret: S = a·B = b·A = ab·G
 *
 * Point Addition & Doubling:
 * - P + Q: Draw line through P and Q, find third intersection, reflect
 * - 2P: Draw tangent at P, find intersection, reflect
 */
class ECC {

    companion object {
        /**
         * Standard curves (simplified for demonstration)
         * In production, use standard curves like secp256k1, P-256, etc.
         */

        /**
         * Small test curve for educational purposes
         * Based on the example from ECC.ipynb: E: y² = x³ + 2x + 2 (mod 17)
         */
        fun getTestCurve(): ECCCurve {
            val p = BigInteger.valueOf(17)
            val a = BigInteger.valueOf(2)
            val b = BigInteger.valueOf(2)
            val G = ECCPoint(BigInteger.valueOf(5), BigInteger.valueOf(1))
            val n = BigInteger.valueOf(19) // Order of the curve

            return ECCCurve(a, b, p, G, n, "Test-Curve-17")
        }

        /**
         * Larger curve for practical use (simplified version of secp256k1-like curve)
         * Note: This is educational - use standard curves in production!
         */
        fun getSecureCurve(): ECCCurve {
            // Using a 256-bit prime
            val p = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
            val a = BigInteger.ZERO
            val b = BigInteger.valueOf(7)

            // Generator point (simplified)
            val Gx = BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
            val Gy = BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
            val G = ECCPoint(Gx, Gy)

            val n = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

            return ECCCurve(a, b, p, G, n, "secp256k1-like")
        }

        /**
         * Generate ECC key pair
         */
        @RequiresApi(Build.VERSION_CODES.TIRAMISU)
        fun generateKeyPair(curve: ECCCurve = getTestCurve()): ECCKeyPair {
            val random = SecureRandom()

            // Generate private key: random d in [1, n-1]
            var d: BigInteger
            do {
                d = BigInteger(curve.n.bitLength(), random)
            } while (d >= curve.n || d <= BigInteger.ZERO)

            // Compute public key: Q = d·G
            val Q = scalarMultiply(curve.G, d, curve)

            return ECCKeyPair(
                ECCPublicKey(Q, curve),
                ECCPrivateKey(d, curve)
            )
        }

        /**
         * Generate key pair with specific private key (for testing)
         */
        @RequiresApi(Build.VERSION_CODES.TIRAMISU)
        fun generateKeyPairFromPrivate(d: BigInteger, curve: ECCCurve = getTestCurve()): ECCKeyPair {
            require(d >= BigInteger.ONE && d < curve.n) {
                "Private key must be in range [1, n-1]"
            }

            val Q = scalarMultiply(curve.G, d, curve)

            return ECCKeyPair(
                ECCPublicKey(Q, curve),
                ECCPrivateKey(d, curve)
            )
        }

        /**
         * Point addition on elliptic curve
         * P + Q = R
         */
        @RequiresApi(Build.VERSION_CODES.TIRAMISU)
        fun pointAdd(P: ECCPoint, Q: ECCPoint, curve: ECCCurve): ECCPoint {
            // Handle point at infinity
            if (P.isInfinity()) return Q
            if (Q.isInfinity()) return P

            val p = curve.p
            val a = curve.a

            // If P = -Q (same x, opposite y), result is point at infinity
            if (P.x == Q.x && P.y == (p - Q.y).mod(p)) {
                return ECCPoint.INFINITY
            }

            // Calculate slope
            val slope = if (P == Q) {
                // Point doubling: s = (3x₁² + a) / (2y₁)
                val numerator = (BigInteger.valueOf(3) * P.x * P.x + a).mod(p)
                val denominator = (BigInteger.TWO * P.y).mod(p)
                (numerator * MathUtils.modularInverse(denominator, p)).mod(p)
            } else {
                // Point addition: s = (y₂ - y₁) / (x₂ - x₁)
                val numerator = (Q.y - P.y).mod(p)
                val denominator = (Q.x - P.x).mod(p)
                (numerator * MathUtils.modularInverse(denominator, p)).mod(p)
            }

            // Calculate result point
            // x₃ = s² - x₁ - x₂
            val x3 = (slope * slope - P.x - Q.x).mod(p)
            // y₃ = s(x₁ - x₃) - y₁
            val y3 = (slope * (P.x - x3) - P.y).mod(p)

            return ECCPoint(x3, y3)
        }

        /**
         * Scalar multiplication: k·P
         * Uses double-and-add algorithm for efficiency
         */
        @RequiresApi(Build.VERSION_CODES.TIRAMISU)
        fun scalarMultiply(P: ECCPoint, k: BigInteger, curve: ECCCurve): ECCPoint {
            if (k == BigInteger.ZERO || P.isInfinity()) {
                return ECCPoint.INFINITY
            }

            if (k < BigInteger.ZERO) {
                throw IllegalArgumentException("Scalar must be non-negative")
            }

            // Binary representation of k
            val bits = k.toString(2)

            var result = ECCPoint.INFINITY
            var addend = P

            // Double-and-add algorithm
            for (i in bits.length - 1 downTo 0) {
                if (bits[i] == '1') {
                    result = pointAdd(result, addend, curve)
                }
                addend = pointAdd(addend, addend, curve) // Double
            }

            return result
        }

        /**
         * Verify a point is on the curve
         */
        fun verifyPoint(point: ECCPoint, curve: ECCCurve): Boolean {
            if (point.isInfinity()) return true

            val p = curve.p
            val a = curve.a
            val b = curve.b

            // Check: y² = x³ + ax + b (mod p)
            val lhs = (point.y * point.y).mod(p)
            val rhs = (point.x.pow(3) + a * point.x + b).mod(p)

            return lhs == rhs
        }
    }

    /**
     * Point addition on elliptic curve (instance method for backward compatibility)
     * P + Q = R
     */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    fun pointAdd(P: ECCPoint, Q: ECCPoint, curve: ECCCurve): ECCPoint {
        return Companion.pointAdd(P, Q, curve)
    }

    /**
     * Scalar multiplication: k·P (instance method for backward compatibility)
     * Uses double-and-add algorithm for efficiency
     */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    fun scalarMultiply(P: ECCPoint, k: BigInteger, curve: ECCCurve): ECCPoint {
        return Companion.scalarMultiply(P, k, curve)
    }

    /**
     * ECDH: Generate shared secret
     * Alice: S = a·B (a is Alice's private key, B is Bob's public key)
     * Bob: S = b·A (b is Bob's private key, A is Alice's public key)
     * Both get the same shared secret S
     */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    fun generateSharedSecret(
        privateKey: ECCPrivateKey,
        publicKey: ECCPublicKey
    ): ECCPoint {
        require(privateKey.curve == publicKey.curve) {
            "Keys must use the same curve"
        }

        return scalarMultiply(publicKey.Q, privateKey.d, privateKey.curve)
    }

    /**
     * Encrypt a message using ECC (hybrid encryption)
     * 1. Generate ephemeral key pair (k, R = k·G)
     * 2. Compute shared secret S = k·Q (Q is recipient's public key)
     * 3. Derive symmetric key from S
     * 4. Encrypt message with symmetric key
     * 5. Send (R, ciphertext)
     */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    fun encrypt(message: String, recipientPublicKey: ECCPublicKey): ECCEncryptedMessage {
        val curve = recipientPublicKey.curve
        val random = SecureRandom()

        // Generate ephemeral key k
        var k: BigInteger
        do {
            k = BigInteger(curve.n.bitLength(), random)
        } while (k >= curve.n || k <= BigInteger.ZERO)

        // Compute R = k·G
        val R = scalarMultiply(curve.G, k, curve)

        // Compute shared secret S = k·Q
        val S = scalarMultiply(recipientPublicKey.Q, k, curve)

        // Derive symmetric key from shared secret (using SHA-256)
        val symmetricKey = deriveKey(S)

        // XOR message with key (simple encryption for demonstration)
        val messageBytes = message.toByteArray()
        val ciphertext = xorWithKey(messageBytes, symmetricKey)

        return ECCEncryptedMessage(R, ciphertext, curve)
    }

    /**
     * Decrypt a message using ECC
     * 1. Receive (R, ciphertext)
     * 2. Compute shared secret S = d·R (d is recipient's private key)
     * 3. Derive same symmetric key from S
     * 4. Decrypt ciphertext
     */
    fun decrypt(encryptedMessage: ECCEncryptedMessage, recipientPrivateKey: ECCPrivateKey): String {
        require(encryptedMessage.curve == recipientPrivateKey.curve) {
            "Encrypted message and private key must use the same curve"
        }

        // Compute shared secret S = d·R
        val S = scalarMultiply(encryptedMessage.R, recipientPrivateKey.d, recipientPrivateKey.curve)

        // Derive same symmetric key
        val symmetricKey = deriveKey(S)

        // Decrypt ciphertext
        val messageBytes = xorWithKey(encryptedMessage.ciphertext, symmetricKey)

        return String(messageBytes)
    }

    /**
     * Derive symmetric key from shared secret point using SHA-256
     */
    private fun deriveKey(point: ECCPoint): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        // Use x-coordinate of shared secret point
        val xBytes = point.x.toByteArray()
        return digest.digest(xBytes)
    }

    /**
     * XOR operation for simple symmetric encryption
     * In production, use AES or another strong cipher
     */
    private fun xorWithKey(data: ByteArray, key: ByteArray): ByteArray {
        val result = ByteArray(data.size)
        for (i in data.indices) {
            result[i] = (data[i].toInt() xor key[i % key.size].toInt()).toByte()
        }
        return result
    }

    /**
     * Verify a point is on the curve
     */
    fun verifyPoint(point: ECCPoint, curve: ECCCurve): Boolean {
        if (point.isInfinity()) return true

        val p = curve.p
        val a = curve.a
        val b = curve.b

        // Check: y² = x³ + ax + b (mod p)
        val lhs = (point.y * point.y).mod(p)
        val rhs = (point.x.pow(3) + a * point.x + b).mod(p)

        return lhs == rhs
    }
}

/**
 * Encrypted message structure for ECC
 */
data class ECCEncryptedMessage(
    val R: ECCPoint,           // Ephemeral public key
    val ciphertext: ByteArray, // Encrypted message
    val curve: ECCCurve        // Curve used
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ECCEncryptedMessage
        if (R != other.R) return false
        if (!ciphertext.contentEquals(other.ciphertext)) return false
        if (curve != other.curve) return false
        return true
    }

    override fun hashCode(): Int {
        var result = R.hashCode()
        result = 31 * result + ciphertext.contentHashCode()
        result = 31 * result + curve.hashCode()
        return result
    }

    override fun toString(): String {
        return """
            ECCEncryptedMessage:
              R = ${R.toCompactString()}
              Ciphertext = ${ciphertext.size} bytes
              Curve = ${curve.name}
        """.trimIndent()
    }
}