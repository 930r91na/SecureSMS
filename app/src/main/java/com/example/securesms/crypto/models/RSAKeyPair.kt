package com.example.securesms.crypto.models
import java.math.BigInteger


/**
 * RSA Public Key: (e, n)
 */
data class RSAPublicKey(
    val e: BigInteger, // Public exponent
    val n: BigInteger  // Modulus
) {
    override fun toString(): String {
        return "RSAPublicKey(e=$e, n=$n)"
    }

    fun toCompactString(): String {
        return "e=$e\nn=${n.toString(16).take(32)}..."
    }
}

/**
 * RSA Private Key: (d, n, p, q)
 */
data class RSAPrivateKey(
    val d: BigInteger, // Private exponent
    val n: BigInteger, // Modulus
    val p: BigInteger, // Prime p
    val q: BigInteger  // Prime q
) {
    override fun toString(): String {
        return "RSAPrivateKey(d=$d, n=$n)"
    }

    fun toCompactString(): String {
        return "d=${d.toString(16).take(32)}...\nn=${n.toString(16).take(32)}..."
    }
}

/**
 * RSA Key Pair containing both public and private keys
 * Used by handshake and certificate code
 */
data class RSAKeyPair(
    val publicKey: RSAPublicKey,
    val privateKey: RSAPrivateKey
)