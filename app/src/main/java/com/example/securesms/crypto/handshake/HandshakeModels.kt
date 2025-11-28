package com.example.securesms.crypto.handshake

import AuthPublicKey
import android.os.Build
import android.util.Base64
import androidx.annotation.RequiresApi
import com.example.securesms.crypto.models.*
import java.math.BigInteger

/**
 * Parse certificate from string format
 * Format: "CERT:SUBJECT=...;ALGORITHM=...;KEY_TYPE=...;..."
 */
fun parseCertificate(str: String): Certificate {
    val parts = str.removePrefix("CERT:").split(";")
    var subject = ""
    var algorithm = ""
    var keyType = ""
    var validFrom = 0L
    var validTo = 0L
    var sig = ByteArray(0)

    // RSA key components
    var n: BigInteger? = null
    var e: BigInteger? = null

    // ECDSA key components
    var qx: BigInteger? = null
    var qy: BigInteger? = null
    var curveName: String? = null

    for (part in parts) {
        when {
            part.startsWith("SUBJECT=") -> subject = part.substringAfter("SUBJECT=")
            part.startsWith("ALGORITHM=") -> algorithm = part.substringAfter("ALGORITHM=")
            part.startsWith("KEY_TYPE=") -> keyType = part.substringAfter("KEY_TYPE=")
            part.startsWith("N=") -> n = BigInteger(part.substringAfter("N="))
            part.startsWith("E=") -> e = BigInteger(part.substringAfter("E="))
            part.startsWith("QX=") -> qx = BigInteger(part.substringAfter("QX="))
            part.startsWith("QY=") -> qy = BigInteger(part.substringAfter("QY="))
            part.startsWith("CURVE=") -> curveName = part.substringAfter("CURVE=")
            part.startsWith("FROM=") -> validFrom = part.substringAfter("FROM=").toLong()
            part.startsWith("TO=") -> validTo = part.substringAfter("TO=").toLong()
            part.startsWith("SIG=") -> sig = part.substringAfter("SIG=").hexToBytes()
        }
    }

    // Reconstruct public key based on type
    val publicKey: AuthPublicKey = when (keyType) {
        "RSA" -> {
            require(n != null && e != null) { "RSA key missing n or e" }
            AuthPublicKey.RSAAuth(RSAPublicKey(e, n))
        }
        "ECDSA" -> {
            require(qx != null && qy != null && curveName != null) { "ECDSA key missing components" }
            val curve = getCurveByName(curveName)
            val point = ECCPoint(qx, qy)
            AuthPublicKey.ECDSAAuth(ECCPublicKey(point, curve))
        }
        else -> throw IllegalArgumentException("Unknown key type: $keyType")
    }

    // Reconstruct the data that was signed
    val dataStr = "$subject:$algorithm:$validFrom:$validTo"

    return Certificate(
        subject = subject,
        publicKey = publicKey,
        algorithm = algorithm,
        validFrom = validFrom,
        validTo = validTo,
        signatureData = dataStr.toByteArray(),
        signature = sig
    )
}

/**
 * Get curve by name
 */
@RequiresApi(Build.VERSION_CODES.TIRAMISU)
private fun getCurveByName(name: String): ECCCurve {
    return when (name) {
        "secp256k1-like" -> com.example.securesms.crypto.asymmetric.ECC.getSecureCurve()
        "P-256" -> com.example.securesms.crypto.asymmetric.ECC.getP256Curve()
        "P-224" -> com.example.securesms.crypto.asymmetric.ECC.getP224Curve()
        "P-384" -> com.example.securesms.crypto.asymmetric.ECC.getP384Curve()
        "P-521" -> com.example.securesms.crypto.asymmetric.ECC.getP521Curve()
        "Test-Curve-17" -> com.example.securesms.crypto.asymmetric.ECC.getTestCurve()
        else -> throw IllegalArgumentException("Unknown curve: $name")
    }
}

/**
 * ClientHello Message
 */
data class ClientHelloMessage(
    val clientRandom: ByteArray,
    val cipherSuites: List<String>
) {
    override fun toString() = "${clientRandom.b64()}|${cipherSuites.joinToString(",")}"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ClientHelloMessage
        if (!clientRandom.contentEquals(other.clientRandom)) return false
        if (cipherSuites != other.cipherSuites) return false
        return true
    }

    override fun hashCode(): Int {
        var result = clientRandom.contentHashCode()
        result = 31 * result + cipherSuites.hashCode()
        return result
    }

    companion object {
        fun fromString(str: String): ClientHelloMessage {
            val parts = str.split("|")
            return ClientHelloMessage(parts[0].u64(), parts[1].split(","))
        }
    }
}

/**
 * ServerHello Message
 */
data class ServerHelloMessage(
    val serverRandom: ByteArray,
    val certificate: Certificate,
    val ephemeralPublicKey: ECCPoint,
    val signature: ByteArray
) {
    override fun toString(): String {
        return "${serverRandom.b64()}|${certificate.toBytes().toString(Charsets.UTF_8)}|${ephemeralPublicKey.x}:${ephemeralPublicKey.y}|${signature.b64()}"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ServerHelloMessage
        if (!serverRandom.contentEquals(other.serverRandom)) return false
        if (certificate != other.certificate) return false
        if (ephemeralPublicKey != other.ephemeralPublicKey) return false
        if (!signature.contentEquals(other.signature)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = serverRandom.contentHashCode()
        result = 31 * result + certificate.hashCode()
        result = 31 * result + ephemeralPublicKey.hashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }

    companion object {
        fun fromString(str: String): ServerHelloMessage {
            val parts = str.split("|")
            val cert = parseCertificate(parts[1])
            val pointParts = parts[2].split(":")
            val point = ECCPoint(BigInteger(pointParts[0]), BigInteger(pointParts[1]))
            return ServerHelloMessage(parts[0].u64(), cert, point, parts[3].u64())
        }
    }
}

/**
 * ClientKeyExchange Message
 */
data class ClientKeyExchangeMessage(
    val certificate: Certificate,
    val ephemeralPublicKey: ECCPoint,
    val signature: ByteArray
) {
    override fun toString(): String {
        return "${certificate.toBytes().toString(Charsets.UTF_8)}|${ephemeralPublicKey.x}:${ephemeralPublicKey.y}|${signature.b64()}"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ClientKeyExchangeMessage
        if (certificate != other.certificate) return false
        if (ephemeralPublicKey != other.ephemeralPublicKey) return false
        if (!signature.contentEquals(other.signature)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = certificate.hashCode()
        result = 31 * result + ephemeralPublicKey.hashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }

    companion object {
        fun fromString(str: String): ClientKeyExchangeMessage {
            val parts = str.split("|")
            val cert = parseCertificate(parts[0])
            val pointParts = parts[1].split(":")
            val point = ECCPoint(BigInteger(pointParts[0]), BigInteger(pointParts[1]))
            return ClientKeyExchangeMessage(cert, point, parts[2].u64())
        }
    }
}

/**
 * Finished Message
 */
data class FinishedMessage(
    val verifyData: ByteArray
) {
    override fun toString() = verifyData.b64()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as FinishedMessage
        return verifyData.contentEquals(other.verifyData)
    }

    override fun hashCode(): Int = verifyData.contentHashCode()
}
private fun ByteArray.b64(): String = Base64.encodeToString(this, Base64.NO_WRAP)
private fun String.u64(): ByteArray = Base64.decode(this, Base64.NO_WRAP)
private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()