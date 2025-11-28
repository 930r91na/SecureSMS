package com.example.securesms.crypto.models

import AuthPublicKey

/**
 * Generic Certificate that works with both RSA and ECDSA
 */
data class Certificate(
    val subject: String,              // Phone number
    val publicKey: AuthPublicKey,     // Generic public key (RSA or ECDSA)
    val algorithm: String,            // "RSA-2048" or "ECDSA-P256"
    val validFrom: Long,              // Unix timestamp
    val validTo: Long,                // Unix timestamp
    val signatureData: ByteArray,     // Data that was signed
    val signature: ByteArray          // Signature bytes
) {
    fun toBytes(): ByteArray {
        // Serialize certificate for transmission
        val sb = StringBuilder()
        sb.append("CERT:")
        sb.append("SUBJECT=$subject;")
        sb.append("ALGORITHM=$algorithm;")

        // Serialize public key based on type
        when (publicKey) {
            is AuthPublicKey.RSAAuth -> {
                sb.append("KEY_TYPE=RSA;")
                sb.append("N=${publicKey.key.n};")
                sb.append("E=${publicKey.key.e};")
            }
            is AuthPublicKey.ECDSAAuth -> {
                sb.append("KEY_TYPE=ECDSA;")
                sb.append("QX=${publicKey.key.Q.x};")
                sb.append("QY=${publicKey.key.Q.y};")
                sb.append("CURVE=${publicKey.key.curve.name};")
            }
        }

        sb.append("FROM=$validFrom;")
        sb.append("TO=$validTo;")
        sb.append("SIG=${signature.toHex()}")
        return sb.toString().toByteArray()
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    companion object {
        fun fromBytes(data: ByteArray): Certificate? {
            // Parse certificate from bytes
            // Implementation details...
            return null
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as Certificate
        if (subject != other.subject) return false
        if (publicKey != other.publicKey) return false
        if (algorithm != other.algorithm) return false
        if (validFrom != other.validFrom) return false
        if (validTo != other.validTo) return false
        if (!signatureData.contentEquals(other.signatureData)) return false
        if (!signature.contentEquals(other.signature)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = subject.hashCode()
        result = 31 * result + publicKey.hashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + validFrom.hashCode()
        result = 31 * result + validTo.hashCode()
        result = 31 * result + signatureData.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "Certificate(subject='$subject', algorithm='$algorithm')"
    }
}