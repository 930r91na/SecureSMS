package com.example.securesms.crypto.models

data class Certificate(
    val subject: String,              // Phone number
    val publicKey: RSAPublicKey,      // RSA public key
    val validFrom: Long,              // Unix timestamp
    val validTo: Long,                // Unix timestamp
    val signatureData: ByteArray,     // Data that was signed
    val signature: ByteArray          // RSA signature
) {
    fun toBytes(): ByteArray {
        // Serialize certificate for transmission
        val sb = StringBuilder()
        sb.append("CERT:")
        sb.append("SUBJECT=$subject;")
        sb.append("N=${publicKey.n};")
        sb.append("E=${publicKey.e};")
        sb.append("FROM=$validFrom;")
        sb.append("TO=$validTo;")
        sb.append("SIG=${signature.toHex()};")
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
}