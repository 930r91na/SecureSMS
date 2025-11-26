package com.example.securesms.crypto.handshake

import AuthKeyPair
import AuthPrivateKey
import AuthPublicKey
import AuthenticationProvider
import android.os.Build
import androidx.annotation.RequiresApi
import com.example.securesms.crypto.asymmetric.ECC
import com.example.securesms.crypto.hash.HMAC
import com.example.securesms.crypto.hash.SHA256
import com.example.securesms.crypto.models.*
import com.example.securesms.crypto.symmetric.KeyDerivation
import java.security.SecureRandom

/**
 * TLS-style Handshake with Pluggable Authentication
 *
 * Supports both RSA and ECDSA authentication via AuthenticationProvider
 */
@RequiresApi(Build.VERSION_CODES.TIRAMISU)
class TLSHandshake(
    private val myPhoneNumber: String,
    private val authProvider: AuthenticationProvider
) {
    private val ecc = ECC()
    private val sha256 = SHA256()
    private val hmac = HMAC()
    private val kdf = KeyDerivation()
    private val certManager = CertificateManager(authProvider)
    private val random = SecureRandom()

    // Identity keys - generated on init
    private var myIdentityKeyPair: AuthKeyPair? = null

    // State
    var state = HandshakeState.IDLE
        private set

    // Handshake Data
    private var clientRandom: ByteArray? = null
    private var serverRandom: ByteArray? = null
    private var myEphemeralKeyPair: ECCKeyPair? = null
    private var peerEphemeralPublicKey: ECCPoint? = null
    private var peerIdentityKey: AuthPublicKey? = null

    private var masterSecret: ByteArray? = null
    var sessionKeys: SessionKeys? = null
        private set

    // Transcript for integrity check
    private val transcript = StringBuilder()

    init {
        // Generate identity key pair on initialization
        myIdentityKeyPair = authProvider.generateKeyPair()
    }

    /** CLIENT: Step 1 - Generate ClientHello */
    fun generateClientHello(): ClientHelloMessage {
        check(state == HandshakeState.IDLE) { "Invalid state for ClientHello" }

        clientRandom = ByteArray(32).apply { random.nextBytes(this) }

        // Include algorithm in cipher suite
        val cipherSuite = "ECDH-${authProvider.algorithm}-AES256-GCM-SHA256"
        val msg = ClientHelloMessage(clientRandom!!, listOf(cipherSuite))

        transcript.append(msg.toString())
        state = HandshakeState.CLIENT_HELLO_SENT
        return msg
    }

    /** SERVER: Step 2 - Process ClientHello, Generate ServerHello */
    fun handleClientHello(msg: ClientHelloMessage): ServerHelloMessage {
        check(state == HandshakeState.IDLE) { "Invalid state for ServerHello" }

        clientRandom = msg.clientRandom
        transcript.append(msg.toString())

        serverRandom = ByteArray(32).apply { random.nextBytes(this) }

        // Generate Ephemeral ECDH Key
        myEphemeralKeyPair = ECC.generateKeyPair(ECC.getSecureCurve())

        // Generate certificate using the generic CertificateManager
        val myCert = certManager.generateSelfSignedCertificate(
            myPhoneNumber,
            myIdentityKeyPair!!
        )

        // Sign the params (Authentication)
        val paramsToSign = clientRandom!! + serverRandom!! +
                myEphemeralKeyPair!!.publicKey.Q.x.toByteArray()

        // Extract private key and sign
        val privateKey = extractPrivateKey(myIdentityKeyPair!!)
        val signature = authProvider.sign(paramsToSign, privateKey)

        val serverHello = ServerHelloMessage(
            serverRandom!!,
            myCert,
            myEphemeralKeyPair!!.publicKey.Q,
            signature
        )

        transcript.append(serverHello.toString())
        state = HandshakeState.SERVER_HELLO_SENT
        return serverHello
    }

    /** CLIENT: Step 3 - Process ServerHello, Generate KeyExchange */
    fun handleServerHello(msg: ServerHelloMessage): ClientKeyExchangeMessage {
        check(state == HandshakeState.CLIENT_HELLO_SENT) { "Invalid state for handling ServerHello" }
        transcript.append(msg.toString())

        serverRandom = msg.serverRandom
        peerIdentityKey = msg.certificate.publicKey  // ✅ Now AuthPublicKey
        peerEphemeralPublicKey = msg.ephemeralPublicKey

        // Verify Certificate
        if (!certManager.verifyCertificate(msg.certificate)) {
            throw SecurityException("Invalid Server Certificate")
        }

        // Verify Signature (Auth) - using authProvider
        val paramsSigned = clientRandom!! + serverRandom!! +
                peerEphemeralPublicKey!!.x.toByteArray()

        if (!authProvider.verify(paramsSigned, msg.signature, peerIdentityKey!!)) {
            throw SecurityException("Server Signature Invalid")
        }

        // Generate Client Ephemeral Key
        myEphemeralKeyPair = ECC.generateKeyPair(ECC.getSecureCurve())
        val myCert = certManager.generateSelfSignedCertificate(
            myPhoneNumber,
            myIdentityKeyPair!!
        )

        // Compute Shared Secret (ECDH)
        val sharedPoint = ecc.generateSharedSecret(
            myEphemeralKeyPair!!.privateKey,
            ECCPublicKey(peerEphemeralPublicKey!!, myEphemeralKeyPair!!.publicKey.curve)
        )
        deriveKeys(sharedPoint)

        // Sign parameters
        val paramsToSign = clientRandom!! + serverRandom!! +
                myEphemeralKeyPair!!.publicKey.Q.x.toByteArray()

        val privateKey = extractPrivateKey(myIdentityKeyPair!!)
        val signature = authProvider.sign(paramsToSign, privateKey)

        val cke = ClientKeyExchangeMessage(
            myCert,
            myEphemeralKeyPair!!.publicKey.Q,
            signature
        )

        transcript.append(cke.toString())
        state = HandshakeState.KEYS_DERIVED
        return cke
    }

    /** SERVER: Step 4 - Process Client KeyExchange */
    fun handleClientKeyExchange(msg: ClientKeyExchangeMessage) {
        check(state == HandshakeState.SERVER_HELLO_SENT) { "Invalid state for handling ClientKeyExchange" }
        transcript.append(msg.toString())

        peerIdentityKey = msg.certificate.publicKey  // ✅ Now AuthPublicKey
        peerEphemeralPublicKey = msg.ephemeralPublicKey

        // Verify Certificate
        if (!certManager.verifyCertificate(msg.certificate)) {
            throw SecurityException("Invalid Client Certificate")
        }

        // Verify Signature - using authProvider
        val paramsSigned = clientRandom!! + serverRandom!! +
                peerEphemeralPublicKey!!.x.toByteArray()

        if (!authProvider.verify(paramsSigned, msg.signature, peerIdentityKey!!)) {
            throw SecurityException("Client Signature Invalid")
        }

        // Compute Shared Secret (ECDH)
        val sharedPoint = ecc.generateSharedSecret(
            myEphemeralKeyPair!!.privateKey,
            ECCPublicKey(peerEphemeralPublicKey!!, myEphemeralKeyPair!!.publicKey.curve)
        )
        deriveKeys(sharedPoint)

        state = HandshakeState.KEYS_DERIVED
    }

    private fun deriveKeys(sharedPoint: ECCPoint) {
        // Use x-coordinate of shared secret as per standard ECDH
        val preMasterSecret = sharedPoint.x.toByteArray()

        // Derive Master Secret
        masterSecret = kdf.deriveMasterSecret(preMasterSecret, clientRandom!!, serverRandom!!)

        // Derive Session Keys
        sessionKeys = kdf.deriveSessionKeys(masterSecret!!, clientRandom!!, serverRandom!!)
    }

    /** Generate Finished Message (HMAC of transcript) */
    fun generateFinished(): FinishedMessage {
        check(state == HandshakeState.KEYS_DERIVED) { "Cannot generate Finished - keys not derived" }

        val transcriptBytes = transcript.toString().toByteArray()
        val key = sessionKeys!!.clientMacKey
        val verifyData = hmac.compute(key, transcriptBytes)

        state = HandshakeState.ESTABLISHED
        return FinishedMessage(verifyData)
    }

    /**
     * Get the authentication algorithm being used
     */
    fun getAuthAlgorithm(): String = authProvider.algorithm

    // ========== Helper Methods ==========

    /**
     * Extract private key from AuthKeyPair wrapper
     */
    private fun extractPrivateKey(keyPair: AuthKeyPair): AuthPrivateKey {
        return when (keyPair) {
            is AuthKeyPair.RSAAuth -> AuthPrivateKey.RSAAuth(keyPair.keyPair.privateKey)
            is AuthKeyPair.ECDSAAuth -> AuthPrivateKey.ECDSAAuth(keyPair.keyPair.privateKey)
        }
    }
}