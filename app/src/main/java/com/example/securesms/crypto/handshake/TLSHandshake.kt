// File: app/src/main/java/com/example/securesms/crypto/handshake/TLSHandshake.kt
package com.example.securesms.crypto.handshake

import android.os.Build
import androidx.annotation.RequiresApi
import com.example.securesms.crypto.asymmetric.ECC
import com.example.securesms.crypto.asymmetric.RSA
import com.example.securesms.crypto.hash.HMAC
import com.example.securesms.crypto.hash.SHA256
import com.example.securesms.crypto.models.*
import com.example.securesms.crypto.symmetric.KeyDerivation
import com.example.securesms.crypto.utils.MathUtils
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Base64

@RequiresApi(Build.VERSION_CODES.TIRAMISU)
class TLSHandshake(
    private val myPhoneNumber: String,
    private val myIdentityKeyPair: RSAKeyPair
) {
    private val ecc = ECC()
    private val sha256 = SHA256()
    private val hmac = HMAC()
    private val kdf = KeyDerivation()
    private val certManager = CertificateManager()
    private val random = SecureRandom()

    // State
    var state = HandshakeState.IDLE
        private set

    // Handshake Data
    private var clientRandom: ByteArray? = null
    private var serverRandom: ByteArray? = null
    private var myEphemeralKeyPair: ECCKeyPair? = null
    private var peerEphemeralPublicKey: ECCPoint? = null
    private var peerIdentityKey: RSAPublicKey? = null

    private var masterSecret: ByteArray? = null
    var sessionKeys: SessionKeys? = null
        private set

    // Transcript for integrity check
    private val transcript = StringBuilder()

    /** CLIENT: Step 1 - Generate ClientHello */
    fun generateClientHello(): ClientHelloMessage {
        check(state == HandshakeState.IDLE)

        clientRandom = ByteArray(32).apply { random.nextBytes(this) }
        val msg = ClientHelloMessage(clientRandom!!, listOf("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA256"))

        transcript.append(msg.toString())
        state = HandshakeState.CLIENT_HELLO_SENT
        return msg
    }

    /** SERVER: Step 2 - Process ClientHello, Generate ServerHello */
    fun handleClientHello(msg: ClientHelloMessage): ServerHelloMessage {
        check(state == HandshakeState.IDLE)

        clientRandom = msg.clientRandom
        transcript.append(msg.toString())

        serverRandom = ByteArray(32).apply { random.nextBytes(this) }

        // Generate Ephemeral ECDH Key
        myEphemeralKeyPair = ECC.generateKeyPair(ECC.getSecureCurve())
        val myCert = certManager.generateSelfSignedCertificate(myPhoneNumber, myIdentityKeyPair)

        // Sign the params (Authentication)
        val paramsToSign = clientRandom!! + serverRandom!! + myEphemeralKeyPair!!.publicKey.Q.x.toByteArray()
        val hash = sha256.hash(paramsToSign)
        val sigInt = MathUtils.modPow(BigInteger(1, hash), myIdentityKeyPair.privateKey.d, myIdentityKeyPair.privateKey.n)

        val serverHello = ServerHelloMessage(
            serverRandom!!, myCert, myEphemeralKeyPair!!.publicKey.Q, sigInt.toByteArray()
        )

        transcript.append(serverHello.toString())
        state = HandshakeState.SERVER_HELLO_SENT
        return serverHello
    }

    /** CLIENT: Step 3 - Process ServerHello, Generate KeyExchange */
    fun handleServerHello(msg: ServerHelloMessage): ClientKeyExchangeMessage {
        check(state == HandshakeState.CLIENT_HELLO_SENT)
        transcript.append(msg.toString())

        serverRandom = msg.serverRandom
        peerIdentityKey = msg.certificate.publicKey
        peerEphemeralPublicKey = msg.ephemeralPublicKey

        // Verify Certificate
        if (!certManager.verifyCertificate(msg.certificate)) throw SecurityException("Invalid Server Cert")

        // Verify Signature (Auth)
        val paramsSigned = clientRandom!! + serverRandom!! + peerEphemeralPublicKey!!.x.toByteArray()
        val hashToCheck = sha256.hash(paramsSigned)
        val sigInt = BigInteger(1, msg.signature)
        val decryptedHash = MathUtils.modPow(sigInt, peerIdentityKey!!.e, peerIdentityKey!!.n)
        if (decryptedHash != BigInteger(1, hashToCheck)) throw SecurityException("Server Signature Invalid")

        // Generate Client Ephemeral Key
        myEphemeralKeyPair = ECC.generateKeyPair(ECC.getSecureCurve())
        val myCert = certManager.generateSelfSignedCertificate(myPhoneNumber, myIdentityKeyPair)

        // Compute Shared Secret
        val sharedPoint = ecc.generateSharedSecret(myEphemeralKeyPair!!.privateKey, ECCPublicKey(peerEphemeralPublicKey!!, myEphemeralKeyPair!!.publicKey.curve))
        deriveKeys(sharedPoint)

        // Sign parameters
        val paramsToSign = clientRandom!! + serverRandom!! + myEphemeralKeyPair!!.publicKey.Q.x.toByteArray()
        val myHash = sha256.hash(paramsToSign)
        val mySig = MathUtils.modPow(BigInteger(1, myHash), myIdentityKeyPair.privateKey.d, myIdentityKeyPair.privateKey.n)

        val cke = ClientKeyExchangeMessage(myCert, myEphemeralKeyPair!!.publicKey.Q, mySig.toByteArray())
        transcript.append(cke.toString())
        state = HandshakeState.KEYS_DERIVED
        return cke
    }

    /** SERVER: Step 4 - Process Client KeyExchange */
    fun handleClientKeyExchange(msg: ClientKeyExchangeMessage) {
        check(state == HandshakeState.SERVER_HELLO_SENT)
        transcript.append(msg.toString())

        peerIdentityKey = msg.certificate.publicKey
        peerEphemeralPublicKey = msg.ephemeralPublicKey

        if (!certManager.verifyCertificate(msg.certificate)) throw SecurityException("Invalid Client Cert")

        // Verify Signature
        val paramsSigned = clientRandom!! + serverRandom!! + peerEphemeralPublicKey!!.x.toByteArray()
        val hashToCheck = sha256.hash(paramsSigned)
        val sigInt = BigInteger(1, msg.signature)
        val decryptedHash = MathUtils.modPow(sigInt, peerIdentityKey!!.e, peerIdentityKey!!.n)
        if (decryptedHash != BigInteger(1, hashToCheck)) throw SecurityException("Client Signature Invalid")

        // Compute Shared Secret
        val sharedPoint = ecc.generateSharedSecret(myEphemeralKeyPair!!.privateKey, ECCPublicKey(peerEphemeralPublicKey!!, myEphemeralKeyPair!!.publicKey.curve))
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
        val transcriptBytes = transcript.toString().toByteArray()
        // Client uses Client MAC key, Server uses Server MAC key
        val key = if(state == HandshakeState.KEYS_DERIVED) sessionKeys!!.clientMacKey else sessionKeys!!.serverMacKey
        val verifyData = hmac.compute(key, transcriptBytes)
        state = HandshakeState.ESTABLISHED
        return FinishedMessage(verifyData)
    }
}