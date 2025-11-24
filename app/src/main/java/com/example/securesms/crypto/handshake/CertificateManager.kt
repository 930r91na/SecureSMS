package com.example.securesms.crypto.handshake

import com.example.securesms.crypto.asymmetric.RSA
import com.example.securesms.crypto.hash.SHA256
import com.example.securesms.crypto.models.Certificate
import com.example.securesms.crypto.models.RSAKeyPair
import java.math.BigInteger

/**
 * Certificate Manager for self-signed certificates
 * Based on your PKI notes: X.509 format
 *
 * Certificate = {Fields, H(Fields), RSA_Sign(H(Fields))}
 *
 * Simplified format:
 * - Subject (phone number)
 * - Public Key
 * - Valid dates
 * - Signature (self-signed)
 */
class CertificateManager {

    private val rsa = RSA()
    private val sha256 = SHA256()

    /**
     * Generate self-signed certificate
     */
    fun generateSelfSignedCertificate(
        phoneNumber: String,
        keyPair: RSAKeyPair
    ): Certificate {
        val validFrom = System.currentTimeMillis()
        val validTo = validFrom + (365L * 24 * 60 * 60 * 1000) // 1 year

        // Create certificate fields
        val certData = buildString {
            append("SUBJECT=$phoneNumber;")
            append("PUBKEY_N=${keyPair.publicKey.n};")
            append("PUBKEY_E=${keyPair.publicKey.e};")
            append("VALID_FROM=$validFrom;")
            append("VALID_TO=$validTo;")
        }.toByteArray()

        // Hash the certificate data
        val certHash = sha256.hash(certData)

        // Sign with private key
        val signature = rsa.sign(
            BigInteger(1, certHash),
            keyPair.privateKey
        )

        return Certificate(
            subject = phoneNumber,
            publicKey = keyPair.publicKey,
            validFrom = validFrom,
            validTo = validTo,
            signatureData = certData,
            signature = signature.toByteArray()
        )
    }

    /**
     * Verify certificate signature
     */
    fun verifyCertificate(certificate: Certificate): Boolean {
        // Hash the certificate data
        val certHash = sha256.hash(certificate.signatureData)

        // Verify signature with public key from certificate
        return rsa.verify(
            BigInteger(1, certHash),
            BigInteger(1, certificate.signature),
            certificate.publicKey
        )
    }

    /**
     * Check if certificate is valid (time-based)
     */
    fun isCertificateValid(certificate: Certificate): Boolean {
        val now = System.currentTimeMillis()
        return now >= certificate.validFrom && now <= certificate.validTo
    }
}