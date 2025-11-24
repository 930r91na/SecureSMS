package com.example.securesms.crypto.handshake

import android.os.Build
import android.util.Base64
import androidx.annotation.RequiresApi
import com.example.securesms.crypto.models.*
import java.math.BigInteger

// Helper to parse certificates from string format "CERT:SUBJECT=...;N=...;"
fun parseCertificate(str: String): Certificate {
    val parts = str.removePrefix("CERT:").split(";")
    var subject = ""
    var n = BigInteger.ZERO
    var e = BigInteger.ZERO
    var validFrom = 0L
    var validTo = 0L
    var sig = ByteArray(0)

    for (part in parts) {
        when {
            part.startsWith("SUBJECT=") -> subject = part.substringAfter("SUBJECT=")
            part.startsWith("N=") -> n = BigInteger(part.substringAfter("N="))
            part.startsWith("E=") -> e = BigInteger(part.substringAfter("E="))
            part.startsWith("FROM=") -> validFrom = part.substringAfter("FROM=").toLong()
            part.startsWith("TO=") -> validTo = part.substringAfter("TO=").toLong()
            part.startsWith("SIG=") -> sig = part.substringAfter("SIG=").hexToBytes()
        }
    }

    // Reconstruct the data that was signed
    val dataStr = "$subject:$e:$n:$validFrom:$validTo"

    return Certificate(subject, RSAPublicKey(e, n), validFrom, validTo, dataStr.toByteArray(), sig)
}

data class ClientHelloMessage(val clientRandom: ByteArray, val cipherSuites: List<String>) {
    override fun toString() = "${clientRandom.b64()}|${cipherSuites.joinToString(",")}"
    companion object {
        fun fromString(str: String): ClientHelloMessage {
            val parts = str.split("|")
            return ClientHelloMessage(parts[0].u64(), parts[1].split(","))
        }
    }
}

data class ServerHelloMessage(
    val serverRandom: ByteArray,
    val certificate: Certificate,
    val ephemeralPublicKey: ECCPoint,
    val signature: ByteArray
) {
    override fun toString() = "${serverRandom.b64()}|${certificate.toBytes().toString(Charsets.UTF_8)}|${ephemeralPublicKey.x}:${ephemeralPublicKey.y}|${signature.b64()}"

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

data class ClientKeyExchangeMessage(
    val certificate: Certificate,
    val ephemeralPublicKey: ECCPoint,
    val signature: ByteArray
) {
    override fun toString() = "${certificate.toBytes().toString(Charsets.UTF_8)}|${ephemeralPublicKey.x}:${ephemeralPublicKey.y}|${signature.b64()}"

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

data class FinishedMessage(val verifyData: ByteArray) {
    @RequiresApi(Build.VERSION_CODES.O)
    override fun toString() = verifyData.b64()
}


// Utils
private fun ByteArray.b64() = Base64.encodeToString(this, Base64.NO_WRAP)
private fun String.u64() = Base64.decode(this, Base64.NO_WRAP)
private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()