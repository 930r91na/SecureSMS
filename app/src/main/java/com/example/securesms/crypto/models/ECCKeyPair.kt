package com.example.securesms.crypto.models

import java.math.BigInteger

/**
 * ECC Point on an elliptic curve
 * Represents a point (x, y) on the curve: y² = x³ + ax + b (mod p)
 */
data class ECCPoint(
    val x: BigInteger,
    val y: BigInteger
) {
    companion object {
        // Point at infinity (identity element)
        val INFINITY = ECCPoint(BigInteger.ZERO, BigInteger.ZERO)
    }

    fun isInfinity(): Boolean {
        return x == BigInteger.ZERO && y == BigInteger.ZERO
    }

    override fun toString(): String {
        return if (isInfinity()) {
            "Point at Infinity"
        } else {
            "($x, $y)"
        }
    }

    fun toCompactString(): String {
        return if (isInfinity()) {
            "∞"
        } else {
            "(${x.toString(16).take(16)}..., ${y.toString(16).take(16)}...)"
        }
    }
}

/**
 * ECC Curve Parameters
 * Defines the elliptic curve: y² = x³ + ax + b (mod p)
 */
data class ECCCurve(
    val a: BigInteger,          // Curve coefficient a
    val b: BigInteger,          // Curve coefficient b
    val p: BigInteger,          // Prime modulus
    val G: ECCPoint,            // Base point (generator)
    val n: BigInteger,          // Order of G (number of points)
    val name: String = "Custom"
) {
    init {
        // Verify curve is non-singular: 4a³ + 27b² ≠ 0 (mod p)
        val discriminant = (BigInteger.valueOf(4) * a.pow(3) +
                BigInteger.valueOf(27) * b.pow(2)).mod(p)
        require(discriminant != BigInteger.ZERO) {
            "Invalid curve: discriminant is zero (singular curve)"
        }
    }

    override fun toString(): String {
        return """
            Curve $name:
              y² = x³ + ${a}x + $b (mod $p)
              Generator G = $G
              Order n = $n
        """.trimIndent()
    }

    fun toCompactString(): String {
        return "Curve $name: y² = x³ + ${a}x + $b (mod $p)"
    }
}

/**
 * ECC Public Key
 * Public key is a point Q = d·G on the curve
 */
data class ECCPublicKey(
    val Q: ECCPoint,           // Public key point
    val curve: ECCCurve        // Curve parameters
) {
    override fun toString(): String {
        return "ECCPublicKey(Q=$Q, curve=${curve.name})"
    }

    fun toCompactString(): String {
        return "Q=${Q.toCompactString()}"
    }
}

/**
 * ECC Private Key
 * Private key is a random integer d in range [1, n-1]
 */
data class ECCPrivateKey(
    val d: BigInteger,         // Private key scalar
    val curve: ECCCurve        // Curve parameters
) {
    init {
        require(d >= BigInteger.ONE && d < curve.n) {
            "Private key must be in range [1, n-1]"
        }
    }

    override fun toString(): String {
        return "ECCPrivateKey(d=$d, curve=${curve.name})"
    }

    fun toCompactString(): String {
        return "d=${d.toString(16).take(16)}..."
    }
}

/**
 * ECC Key Pair containing both public and private keys
 */
data class ECCKeyPair(
    val publicKey: ECCPublicKey,
    val privateKey: ECCPrivateKey
) {
    init {
        require(publicKey.curve == privateKey.curve) {
            "Public and private keys must use the same curve"
        }
    }

    override fun toString(): String {
        return """
            ECCKeyPair:
              Public: ${publicKey.toCompactString()}
              Private: ${privateKey.toCompactString()}
              Curve: ${privateKey.curve.name}
        """.trimIndent()
    }
}