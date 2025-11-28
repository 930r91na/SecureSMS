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
 * This class handles ECDH key exchange operations.
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
         * Small test curve for educational purposes
         * Based on the example from ECC.ipynb: E: y² = x³ + 2x + 2 (mod 17)
         */
        fun getTestCurve(): ECCCurve {
            val p = BigInteger.valueOf(17)
            val a = BigInteger.valueOf(2)
            val b = BigInteger.valueOf(2)
            val G = ECCPoint(BigInteger.valueOf(5), BigInteger.valueOf(1))
            val n = BigInteger.valueOf(19)
            return ECCCurve(a, b, p, G, n, "Test-Curve-17")
        }

        /**
         * secp256k1-like curve for practical use
         */
        fun getSecureCurve(): ECCCurve {
            val p = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
            val a = BigInteger.ZERO
            val b = BigInteger.valueOf(7)
            val Gx = BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
            val Gy = BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
            val G = ECCPoint(Gx, Gy)
            val n = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
            return ECCCurve(a, b, p, G, n, "secp256k1-like")
        }

        /**
         * P-256 (secp256r1) - NIST standard curve
         * Recommended for most applications
         */
        fun getP256Curve(): ECCCurve {
            val p = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
            val a = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)
            val b = BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
            val Gx = BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16)
            val Gy = BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
            val n = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
            return ECCCurve(a, b, p, ECCPoint(Gx, Gy), n, "P-256")
        }

        fun getP224Curve(): ECCCurve {
            val p = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", 16)
            val a = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", 16)
            val b = BigInteger("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", 16)
            val Gx = BigInteger("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21", 16)
            val Gy = BigInteger("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34", 16)
            val n = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", 16)
            return ECCCurve(a, b, p, ECCPoint(Gx, Gy), n, "P-224")
        }

        fun getP384Curve(): ECCCurve {
            val p = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16)
            val a = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", 16)
            val b = BigInteger("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", 16)
            val Gx = BigInteger("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", 16)
            val Gy = BigInteger("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", 16)
            val n = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16)
            return ECCCurve(a, b, p, ECCPoint(Gx, Gy), n, "P-384")
        }

        fun getP521Curve(): ECCCurve {
            val p = BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)
            val a = BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", 16)
            val b = BigInteger("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", 16)
            val Gx = BigInteger("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", 16)
            val Gy = BigInteger("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", 16)
            val n = BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16)
            return ECCCurve(a, b, p, ECCPoint(Gx, Gy), n, "P-521")
        }

        fun getP192Curve(): ECCCurve {
            val p = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16)
            val a = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", 16)
            val b = BigInteger("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", 16)
            val Gx = BigInteger("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16)
            val Gy = BigInteger("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16)
            val n = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", 16)
            return ECCCurve(a, b, p, ECCPoint(Gx, Gy), n, "P-192")
        }


        /**
         * Generate ECC key pair
         */
        @RequiresApi(Build.VERSION_CODES.TIRAMISU)
        fun generateKeyPair(curve: ECCCurve = getP256Curve()): ECCKeyPair {
            val random = SecureRandom()
            var d: BigInteger
            do {
                d = BigInteger(curve.n.bitLength(), random)
            } while (d >= curve.n || d <= BigInteger.ZERO)

            val Q = scalarMultiply(curve.G, d, curve)
            return ECCKeyPair(ECCPublicKey(Q, curve), ECCPrivateKey(d, curve))
        }

        /**
         * Generate key pair with specific private key (for testing)
         */
        @RequiresApi(Build.VERSION_CODES.TIRAMISU)
        fun generateKeyPairFromPrivate(d: BigInteger, curve: ECCCurve): ECCKeyPair {
            require(d >= BigInteger.ONE && d < curve.n) {
                "Private key must be in range [1, n-1]"
            }
            val Q = scalarMultiply(curve.G, d, curve)
            return ECCKeyPair(ECCPublicKey(Q, curve), ECCPrivateKey(d, curve))
        }

        /**
         * Point addition on elliptic curve: P + Q = R
         */
        @RequiresApi(Build.VERSION_CODES.TIRAMISU)
        fun pointAdd(P: ECCPoint, Q: ECCPoint, curve: ECCCurve): ECCPoint {
            if (P.isInfinity()) return Q
            if (Q.isInfinity()) return P

            val p = curve.p
            val a = curve.a

            // If P = -Q, result is point at infinity
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
            val x3 = (slope * slope - P.x - Q.x).mod(p)
            val y3 = (slope * (P.x - x3) - P.y).mod(p)
            return ECCPoint(x3, y3)
        }

        /**
         * Scalar multiplication: k·P
         * Uses double-and-add algorithm
         */
        @RequiresApi(Build.VERSION_CODES.TIRAMISU)
        fun scalarMultiply(P: ECCPoint, k: BigInteger, curve: ECCCurve): ECCPoint {
            if (k == BigInteger.ZERO || P.isInfinity()) {
                return ECCPoint.INFINITY
            }
            require(k >= BigInteger.ZERO) { "Scalar must be non-negative" }

            val bits = k.toString(2)
            var result = ECCPoint.INFINITY
            var addend = P

            for (i in bits.length - 1 downTo 0) {
                if (bits[i] == '1') {
                    result = pointAdd(result, addend, curve)
                }
                addend = pointAdd(addend, addend, curve)
            }
            return result
        }

        /**
         * Verify a point is on the curve
         */
        fun verifyPoint(point: ECCPoint, curve: ECCCurve): Boolean {
            if (point.isInfinity()) return true
            val p = curve.p
            val lhs = (point.y * point.y).mod(p)
            val rhs = (point.x.pow(3) + curve.a * point.x + curve.b).mod(p)
            return lhs == rhs
        }
    }

    // Instance methods for backward compatibility
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    fun pointAdd(P: ECCPoint, Q: ECCPoint, curve: ECCCurve): ECCPoint =
        Companion.pointAdd(P, Q, curve)

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    fun scalarMultiply(P: ECCPoint, k: BigInteger, curve: ECCCurve): ECCPoint =
        Companion.scalarMultiply(P, k, curve)

    fun verifyPoint(point: ECCPoint, curve: ECCCurve): Boolean =
        Companion.verifyPoint(point, curve)

    /**
     * ECDH: Generate shared secret
     * Alice: S = a·B (a is Alice's private key, B is Bob's public key)
     * Bob: S = b·A (b is Bob's private key, A is Alice's public key)
     */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    fun generateSharedSecret(privateKey: ECCPrivateKey, publicKey: ECCPublicKey): ECCPoint {
        require(privateKey.curve == publicKey.curve) { "Keys must use the same curve" }
        return scalarMultiply(publicKey.Q, privateKey.d, privateKey.curve)
    }

    /**
     * Hybrid encryption using ECC
     * 1. Generate ephemeral key pair (k, R = k·G)
     * 2. Compute shared secret S = k·Q
     * 3. Derive symmetric key from S
     * 4. Encrypt message with symmetric key
     */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    fun encrypt(message: String, recipientPublicKey: ECCPublicKey): ECCEncryptedMessage {
        val curve = recipientPublicKey.curve
        val random = SecureRandom()

        var k: BigInteger
        do {
            k = BigInteger(curve.n.bitLength(), random)
        } while (k >= curve.n || k <= BigInteger.ZERO)

        val R = scalarMultiply(curve.G, k, curve)
        val S = scalarMultiply(recipientPublicKey.Q, k, curve)
        val symmetricKey = deriveKey(S)
        val ciphertext = xorWithKey(message.toByteArray(), symmetricKey)

        return ECCEncryptedMessage(R, ciphertext, curve)
    }

    /**
     * Decrypt using ECC
     */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    fun decrypt(encryptedMessage: ECCEncryptedMessage, recipientPrivateKey: ECCPrivateKey): String {
        require(encryptedMessage.curve == recipientPrivateKey.curve) {
            "Encrypted message and private key must use the same curve"
        }
        val S = scalarMultiply(encryptedMessage.R, recipientPrivateKey.d, recipientPrivateKey.curve)
        val symmetricKey = deriveKey(S)
        val messageBytes = xorWithKey(encryptedMessage.ciphertext, symmetricKey)
        return String(messageBytes)
    }

    private fun deriveKey(point: ECCPoint): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(point.x.toByteArray())
    }

    private fun xorWithKey(data: ByteArray, key: ByteArray): ByteArray {
        return ByteArray(data.size) { i ->
            (data[i].toInt() xor key[i % key.size].toInt()).toByte()
        }
    }
}

/**
 * Encrypted message structure for ECC hybrid encryption
 */
data class ECCEncryptedMessage(
    val R: ECCPoint,
    val ciphertext: ByteArray,
    val curve: ECCCurve
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ECCEncryptedMessage
        return R == other.R && ciphertext.contentEquals(other.ciphertext) && curve == other.curve
    }

    override fun hashCode(): Int {
        var result = R.hashCode()
        result = 31 * result + ciphertext.contentHashCode()
        result = 31 * result + curve.hashCode()
        return result
    }

    override fun toString(): String = """
        ECCEncryptedMessage:
          R = ${R.toCompactString()}
          Ciphertext = ${ciphertext.size} bytes
          Curve = ${curve.name}
    """.trimIndent()
}