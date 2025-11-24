package com.example.securesms.crypto.handshake

import android.os.Build
import androidx.annotation.RequiresApi
import com.example.securesms.crypto.models.Certificate
import com.example.securesms.crypto.models.ECCPoint
import java.util.Base64

// Simple serialization helper using delimiters
@RequiresApi(Build.VERSION_CODES.O)
data class ClientHelloMessage(val clientRandom: ByteArray, val cipherSuites: List<String>) {

    override fun toString() = "${clientRandom.b64()}|${cipherSuites.joinToString(",")}"
    companion object {
        fun fromString(str: String): ClientHelloMessage {
            val parts = str.split("|")
            return ClientHelloMessage(parts[0].u64(), parts[1].split(","))
        }
    }
}

@RequiresApi(Build.VERSION_CODES.O)
data class ServerHelloMessage(
    val serverRandom: ByteArray,
    val certificate: Certificate,
    val ephemeralPublicKey: ECCPoint, // Server's ECDH share
    val signature: ByteArray // Signature over Randoms + Key
) {
    override fun toString() = "${serverRandom.b64()}|${certificate.toBase64()}|${ephemeralPublicKey.x}:${ephemeralPublicKey.y}|${signature.b64()}"
}

@RequiresApi(Build.VERSION_CODES.O)

data class ClientKeyExchangeMessage(
    val certificate: Certificate,
    val ephemeralPublicKey: ECCPoint, // Client's ECDH share
    val signature: ByteArray
) {
    override fun toString() = "${certificate.toBase64()}|${ephemeralPublicKey.x}:${ephemeralPublicKey.y}|${signature.b64()}"
}

@RequiresApi(Build.VERSION_CODES.O)

data class FinishedMessage(val verifyData: ByteArray) {
    @RequiresApi(Build.VERSION_CODES.O)
    override fun toString() = verifyData.b64()
}

// Extension functions for cleaner encoding
@RequiresApi(Build.VERSION_CODES.O)
private fun ByteArray.b64() = Base64.getEncoder().encodeToString(this)
@RequiresApi(Build.VERSION_CODES.O)
private fun String.u64() = Base64.getDecoder().decode(this)
@RequiresApi(Build.VERSION_CODES.O)
private fun Certificate.toBase64() = this.toBytes().b64() // Assuming toBytes implemented in Certificate.kt or we add it