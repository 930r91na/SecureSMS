package com.example.securesms.crypto.handshake

import AuthKeyPair
import AuthPrivateKey
import AuthPublicKey
import AuthenticationProvider
import android.util.Log
import com.example.securesms.crypto.models.*

/**
 * Certificate Manager that works with any AuthenticationProvider
 */
class CertificateManager(
    private val authProvider: AuthenticationProvider
) {

    /**
     * Generate a self-signed certificate
     *
     * @param subject The certificate subject (e.g., phone number)
     * @param keyPair The identity key pair (wrapped in AuthKeyPair)
     * @return Self-signed certificate
     */
    fun generateSelfSignedCertificate(subject: String, keyPair: AuthKeyPair): Certificate {
        val validFrom = System.currentTimeMillis()
        val validTo = validFrom + 315360000000000 // 1 year

        // Extract public key
        val publicKey = when (keyPair) {
            is AuthKeyPair.RSAAuth -> AuthPublicKey.RSAAuth(keyPair.keyPair.publicKey)
            is AuthKeyPair.ECDSAAuth -> AuthPublicKey.ECDSAAuth(keyPair.keyPair.publicKey)
        }

        // Data to sign
        val dataStr = "$subject:${authProvider.algorithm}:$validFrom:$validTo"
        val data = dataStr.toByteArray()

        // Sign using the authentication provider
        val privateKey = when (keyPair) {
            is AuthKeyPair.RSAAuth -> AuthPrivateKey.RSAAuth(keyPair.keyPair.privateKey)
            is AuthKeyPair.ECDSAAuth -> AuthPrivateKey.ECDSAAuth(keyPair.keyPair.privateKey)
        }

        val signature = authProvider.sign(data, privateKey)

        return Certificate(
            subject = subject,
            publicKey = publicKey,
            algorithm = authProvider.algorithm,
            validFrom = validFrom,
            validTo = validTo,
            signatureData = data,
            signature = signature
        )
    }

    /**
     * Verify a certificate
     *
     * @param cert The certificate to verify
     * @return true if valid, false otherwise
     */
    fun verifyCertificate(cert: Certificate): Boolean {

        val now = System.currentTimeMillis()

        // Check expiry
        Log.d("SecureSMS_Cert", "Certificate verification:")
        Log.d("SecureSMS_Cert", "  Current time:  $now")
        Log.d("SecureSMS_Cert", "  Valid from:    ${cert.validFrom}")
        Log.d("SecureSMS_Cert", "  Valid to:      ${cert.validTo}")
        Log.d("SecureSMS_Cert", "  Is expired?    ${now < cert.validFrom || now > cert.validTo}")


        if (now < cert.validFrom || now > cert.validTo) {
            Log.d("SecureSMS_Protocol", "Certificate expired")
            return false
        }

        // Check algorithm matches
        if (cert.algorithm != authProvider.algorithm) {
            Log.d("SecureSMS_Protocol", "Certificate algorithm mismatch")
            return false
        }

        // Verify signature using the authentication provider
        return authProvider.verify(cert.signatureData, cert.signature, cert.publicKey)
    }
}