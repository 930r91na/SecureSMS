package com.example.securesms.crypto.asymmetric

import AuthKeyPair
import AuthPrivateKey
import AuthPublicKey
import AuthenticationProvider
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import com.example.securesms.crypto.hash.SHA256
import com.example.securesms.crypto.models.*
import com.example.securesms.crypto.utils.MathUtils
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * ECDSA (Elliptic Curve Digital Signature Algorithm)
 *
 * Provides digital signatures using elliptic curve cryptography.
 *
 * Signing Process:
 * 1. Hash message: h = SHA-256(message)
 * 2. Generate random k ∈ [1, n-1]
 * 3. Compute R = k·G, set r = R.x mod n
 * 4. Compute s = k^(-1) × (h + r·d) mod n
 * 5. Signature is (r, s)
 *
 * Verification Process:
 * 1. Verify r, s ∈ [1, n-1]
 * 2. Hash message: h = SHA-256(message)
 * 3. Compute w = s^(-1) mod n
 * 4. Compute u1 = h·w mod n, u2 = r·w mod n
 * 5. Compute P = u1·G + u2·Q
 * 6. Verify r == P.x mod n
 */
@RequiresApi(Build.VERSION_CODES.TIRAMISU)
class ECDSA {

    private val random = SecureRandom()

    /**
     * Sign a message using ECDSA
     * @param message The message to sign (will be hashed internally)
     * @param privateKey The signer's ECC private key
     * @return ECDSASignature containing (r, s)
     */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    fun sign(message: ByteArray, privateKey: ECCPrivateKey): ECDSASignature {
        val curve = privateKey.curve
        val n = curve.n
        val d = privateKey.d

        // Hash the message
        val hash = sha256(message)
        val h = BigInteger(1, hash).mod(n)

        // Generate signature (retry if r or s is zero)
        while (true) {
            // Generate random k ∈ [1, n-1]
            var k: BigInteger
            do {
                k = BigInteger(n.bitLength(), random)
            } while (k >= n || k <= BigInteger.ZERO)

            // Compute R = k·G
            val R = ECC.scalarMultiply(curve.G, k, curve)

            // Compute r = R.x mod n
            val r = R.x.mod(n)
            if (r == BigInteger.ZERO) continue

            // Compute k^(-1) mod n
            val kInv = MathUtils.modularInverse(k, n)

            // Compute s = k^(-1) × (h + r·d) mod n
            val s = (kInv * (h + r * d)).mod(n)

            if (s != BigInteger.ZERO) {
                return ECDSASignature(r, s, curve)
            }
        }
    }

    /**
     * Verify an ECDSA signature
     * @param message The original message
     * @param signature The ECDSA signature to verify
     * @param publicKey The signer's ECC public key
     * @return true if signature is valid, false otherwise
     */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    fun verify(message: ByteArray, signature: ECDSASignature, publicKey: ECCPublicKey): Boolean {
        val curve = publicKey.curve
        val n = curve.n
        val r = signature.r
        val s = signature.s
        val Q = publicKey.Q

        // Verify r, s ∈ [1, n-1]
        if (r <= BigInteger.ZERO || r >= n) return false
        if (s <= BigInteger.ZERO || s >= n) return false

        // Hash the message
        val hash = sha256(message)
        val h = BigInteger(1, hash).mod(n)

        // Compute w = s^(-1) mod n
        val w = MathUtils.modularInverse(s, n)

        // Compute u1 = h·w mod n
        val u1 = (h * w).mod(n)

        // Compute u2 = r·w mod n
        val u2 = (r * w).mod(n)

        // Compute P = u1·G + u2·Q
        val u1G = ECC.scalarMultiply(curve.G, u1, curve)
        val u2Q = ECC.scalarMultiply(Q, u2, curve)
        val P = ECC.pointAdd(u1G, u2Q, curve)

        // Verify r == P.x mod n
        val v = P.x.mod(n)

        return v == r
    }

    /**
     * Sign a message hash directly (for when hash is pre-computed)
     */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    fun signHash(hash: ByteArray, privateKey: ECCPrivateKey): ECDSASignature {
        val curve = privateKey.curve
        val n = curve.n
        val d = privateKey.d
        val h = BigInteger(1, hash).mod(n)

        var r: BigInteger
        var s: BigInteger

        while (true) {
            var k: BigInteger
            do {
                k = BigInteger(n.bitLength(), random)
            } while (k >= n || k <= BigInteger.ZERO)

            // Compute R = k·G
            val R = ECC.scalarMultiply(curve.G, k, curve)

            // Compute r = R.x mod n
            val r = R.x.mod(n)
            if (r == BigInteger.ZERO) continue

            // Compute k^(-1) mod n
            val kInv = MathUtils.modularInverse(k, n)

            // Compute s = k^(-1) × (h + r·d) mod n
            val s = (kInv * (h + r * d)).mod(n)

            if (s != BigInteger.ZERO) {
                return ECDSASignature(r, s, curve)
            }


        }
    }

    /**
     * Verify signature on a pre-computed hash
     */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    fun verifyHash(hash: ByteArray, signature: ECDSASignature, publicKey: ECCPublicKey): Boolean {
        val curve = publicKey.curve
        val n = curve.n
        val r = signature.r
        val s = signature.s
        val Q = publicKey.Q

        if (r <= BigInteger.ZERO || r >= n) return false
        if (s <= BigInteger.ZERO || s >= n) return false

        val h = BigInteger(1, hash).mod(n)
        val w = MathUtils.modularInverse(s, n)
        val u1 = (h * w).mod(n)
        val u2 = (r * w).mod(n)

        val u1G = ECC.scalarMultiply(curve.G, u1, curve)
        val u2Q = ECC.scalarMultiply(Q, u2, curve)
        val P = ECC.pointAdd(u1G, u2Q, curve)

        val v = P.x.mod(n)
        return v == r
    }

    private fun sha256(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }
}

/**
 * ECDSA Signature model
 */
data class ECDSASignature(
    val r: BigInteger,
    val s: BigInteger,
    val curve: ECCCurve
) {
    fun toBytes(): ByteArray {
        // Encode as r || s
        val rBytes = r.toByteArray()
        val sBytes = s.toByteArray()
        return rBytes + sBytes
    }

    companion object {
        fun fromBytes(data: ByteArray, curve: ECCCurve): ECDSASignature {
            // Split at midpoint
            val mid = data.size / 2
            val r = BigInteger(1, data.sliceArray(0 until mid))
            val s = BigInteger(1, data.sliceArray(mid until data.size))
            return ECDSASignature(r, s, curve)
        }
    }
}


/**
 * ECDSA Authentication Provider
 *
 * Implements AuthenticationProvider interface for ECDSA-based authentication.
 * Supports multiple standard NIST curves with different security levels.
 *
 * Usage:
 *   val provider = ECDSAAuthProvider(CurveType.P256)
 *   val keyPair = provider.generateKeyPair()
 *   val signature = provider.sign(data, privateKey)
 *   val valid = provider.verify(data, signature, publicKey)
 */
@RequiresApi(Build.VERSION_CODES.TIRAMISU)
class ECDSAAuthProvider(
    private val curveType: CurveType = CurveType.P256
) : AuthenticationProvider {

    /**
     * Standard NIST curves with their security levels
     */
    enum class CurveType(val bits: Int, val securityBits: Int) {
        P192(192, 96),   // ~1024-bit RSA equivalent (deprecated)
        P224(224, 112),  // ~2048-bit RSA equivalent
        P256(256, 128),  // ~3072-bit RSA equivalent (recommended)
        P384(384, 192),  // ~7680-bit RSA equivalent
        P521(521, 256)   // ~15360-bit RSA equivalent
    }

    private val curve: ECCCurve = getCurveForType(curveType)
    private val ecdsa = ECDSA()

    override val algorithm = "ECDSA-${curveType.name}"
    override val keySize = curveType.bits

    /**
     * Generate a new ECDSA key pair
     */
    override fun generateKeyPair(): AuthKeyPair {
        val keyPair = ECC.generateKeyPair(curve)
        return AuthKeyPair.ECDSAAuth(keyPair)
    }

    /**
     * Sign data with ECDSA private key
     */
    override fun sign(data: ByteArray, privateKey: AuthPrivateKey): ByteArray {
        require(privateKey is AuthPrivateKey.ECDSAAuth) {
            "Expected ECDSA private key, got ${privateKey::class.simpleName}"
        }

        val signature = ecdsa.sign(data, privateKey.key)
        return signature.toBytes()
    }

    /**
     * Verify ECDSA signature
     */
    override fun verify(data: ByteArray, signature: ByteArray, publicKey: AuthPublicKey): Boolean {
        require(publicKey is AuthPublicKey.ECDSAAuth) {
            "Expected ECDSA public key, got ${publicKey::class.simpleName}"
        }

        return try {
            val ecdsaSig = ECDSASignature.fromBytes(signature, curve)
            ecdsa.verify(data, ecdsaSig, publicKey.key)
        } catch (e: Exception) {
            Log.d("SecureSMS_Protocol", "ECDSA Signature verification failed")
            false
        }
    }

    /**
     * Get public key size in bytes
     * Compressed point encoding: 1 byte prefix + x-coordinate
     */
    override fun getPublicKeySize(): Int {
        return 1 + (curve.p.bitLength() / 8)
    }

    /**
     * Get signature size in bytes
     * ECDSA signature is (r, s) pair
     */
    override fun getSignatureSize(): Int {
        return 2 * (curve.n.bitLength() / 8)
    }

    /**
     * Get the appropriate curve for the curve type
     */
    private fun getCurveForType(type: CurveType): ECCCurve {
        return when (type) {
            CurveType.P192 -> getP192Curve()
            CurveType.P224 -> getP224Curve()
            CurveType.P256 -> ECC.getP256Curve()
            CurveType.P384 -> getP384Curve()
            CurveType.P521 -> getP521Curve()
        }
    }

    // ========== NIST Curve Definitions ==========

    /**
     * P-192 (secp192r1) - NIST curve
     * Security: ~96 bits
     * ⚠️ Deprecated - use P-256 or higher
     */
    private fun getP192Curve(): ECCCurve {
        val p = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16)
        val a = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", 16)
        val b = BigInteger("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", 16)
        val Gx = BigInteger("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16)
        val Gy = BigInteger("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16)
        val n = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", 16)
        return ECCCurve(a, b, p, ECCPoint(Gx, Gy), n, "P-192")
    }

    /**
     * P-224 (secp224r1) - NIST curve
     * Security: ~112 bits
     * Equivalent to RSA-2048
     */
    private fun getP224Curve(): ECCCurve {
        val p = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", 16)
        val a = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", 16)
        val b = BigInteger("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", 16)
        val Gx = BigInteger("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21", 16)
        val Gy = BigInteger("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34", 16)
        val n = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", 16)
        return ECCCurve(a, b, p, ECCPoint(Gx, Gy), n, "P-224")
    }

    /**
     * P-384 (secp384r1) - NIST curve
     * Security: ~192 bits
     * Equivalent to RSA-7680
     */
    private fun getP384Curve(): ECCCurve {
        val p = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16)
        val a = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", 16)
        val b = BigInteger("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", 16)
        val Gx = BigInteger("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", 16)
        val Gy = BigInteger("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", 16)
        val n = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16)
        return ECCCurve(a, b, p, ECCPoint(Gx, Gy), n, "P-384")
    }

    /**
     * P-521 (secp521r1) - NIST curve
     * Security: ~256 bits
     * Equivalent to RSA-15360
     */
    private fun getP521Curve(): ECCCurve {
        val p = BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)
        val a = BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", 16)
        val b = BigInteger("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", 16)
        val Gx = BigInteger("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", 16)
        val Gy = BigInteger("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", 16)
        val n = BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16)
        return ECCCurve(a, b, p, ECCPoint(Gx, Gy), n, "P-521")
    }
}






