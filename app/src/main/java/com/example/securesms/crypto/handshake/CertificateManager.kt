package com.example.securesms.crypto.handshake

import com.example.securesms.crypto.models.*
import com.example.securesms.crypto.hash.SHA256
import com.example.securesms.crypto.utils.MathUtils
import java.math.BigInteger

class CertificateManager {
    private val sha256 = SHA256()

    fun generateSelfSignedCertificate(subject: String, keyPair: RSAKeyPair): Certificate {
        val validFrom = System.currentTimeMillis()
        val validTo = validFrom + 31536000000 // 1 year

        // Data to sign
        val dataStr = "$subject:${keyPair.publicKey.e}:${keyPair.publicKey.n}:$validFrom:$validTo"
        val data = dataStr.toByteArray()
        val hash = sha256.hash(data)

        // RSA Sign: s = h^d mod n
        val signatureInt = MathUtils.modPow(
            BigInteger(1, hash),
            keyPair.privateKey.d,
            keyPair.privateKey.n
        )

        return Certificate(
            subject = subject,
            publicKey = keyPair.publicKey,
            validFrom = validFrom,
            validTo = validTo,
            signatureData = data,
            signature = signatureInt.toByteArray()
        )
    }

    fun verifyCertificate(cert: Certificate): Boolean {
        // RSA Verify: h' = s^e mod n, check if h' == hash(data)
        val hash = sha256.hash(cert.signatureData)
        val signatureInt = BigInteger(1, cert.signature)

        val decryptedHash = MathUtils.modPow(
            signatureInt,
            cert.publicKey.e,
            cert.publicKey.n
        )

        // Simple comparison of BigIntegers to avoid padding issues with byte arrays
        return decryptedHash == BigInteger(1, hash)
    }
}