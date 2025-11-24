package com.example.securesms.crypto.handshake

import com.example.securesms.crypto.asymmetric.DiffieHellman
import com.example.securesms.crypto.asymmetric.RSA
import com.example.securesms.crypto.hash.HMAC
import com.example.securesms.crypto.hash.SHA256
import com.example.securesms.crypto.models.*
import com.example.securesms.crypto.symmetric.KeyDerivation
import java.math.BigInteger
import java.security.SecureRandom

/**
 * TLS-Style Handshake over SMS
 *
 * Implements the complete handshake flow:
 * 1. ClientHello
 * 2. ServerHello + Certificate
 * 3. ClientKeyExchange + Certificate
 * 4. Key Derivation
 * 5. Finished Messages
 * 6. Secure Channel Established
 */
class TLSHandshake(
    private val myPhoneNumber: String,
    private val myKeyPair: RSAKeyPair
) {

    private val dh = DiffieHellman()
    private val rsa = RSA()
    private val kdf = KeyDerivation()
    private val sha256 = SHA256()
    private val hmac = HMAC()
    private val certManager = CertificateManager()
    private val random = SecureRandom()

    // Handshake state
    private var state = HandshakeState.IDLE
    private var clientRandom: ByteArray? = null
    private var serverRandom: ByteArray? = null
    private var dhParameters: DHParameters? = null
    private var myDHPrivateKey: BigInteger? = null
    private var myDHPublicKey: BigInteger? = null
    private var peerDHPublicKey: BigInteger? = null
    private var preMasterSecret: BigInteger? = null
    private var masterSecret: ByteArray? = null
    private var sessionKeys: SessionKeys? = null

    // Message history for Finished message verification
    private val handshakeMessages = mutableListOf<ByteArray>()

    /**
     * Step 1: CLIENT - Initiate handshake
     * Generate ClientHello message
     */
    fun generateClientHello(): ClientHelloMessage {
        require(state == HandshakeState.IDLE) { "Invalid state for ClientHello" }

        // Generate random nonce
        clientRandom = ByteArray(32).apply { random.nextBytes(this) }

        // Generate DH parameters
        dhParameters = DHParameters.rfc3526Group14() // Standard 2048-bit group

        // Cipher suites we support
        val cipherSuites = listOf(
            "ECDHE-RSA-AES256-GCM-SHA256",
            "DHE-RSA-AES256-GCM-SHA256"
        )

        val message = ClientHelloMessage(
            clientRandom = clientRandom!!,
            cipherSuites = cipherSuites,
            dhParameters = dhParameters!!
        )

        // Record for Finished verification
        handshakeMessages.add(message.toBytes())

        state = HandshakeState.CLIENT_HELLO_SENT

        return message
    }

    /**
     * Step 2: SERVER - Respond to ClientHello
     * Generate ServerHello + Certificate + DH Public Key
     */
    fun generateServerHello(clientHello: ClientHelloMessage): ServerHelloMessage {
        require(state == HandshakeState.IDLE) { "Invalid state for ServerHello" }

        // Record client hello
        handshakeMessages.add(clientHello.toBytes())
        clientRandom = clientHello.clientRandom
        dhParameters = clientHello.dhParameters

        // Generate server random
        serverRandom = ByteArray(32).apply { random.nextBytes(this) }

        // Select cipher suite (first one for simplicity)
        val selectedCipher = clientHello.cipherSuites.first()

        // Generate our DH key pair
        myDHPrivateKey = dh.generatePrivateKey(dhParameters!!)
        myDHPublicKey = dh.generatePublicKey(myDHPrivateKey!!, dhParameters!!)

        // Generate self-signed certificate
        val certificate = certManager.generateSelfSignedCertificate(
            myPhoneNumber,
            myKeyPair
        )

        val message = ServerHelloMessage(
            serverRandom = serverRandom!!,
            selectedCipher = selectedCipher,
            certificate = certificate,
            dhPublicKey = myDHPublicKey!!
        )

        // Record for verification
        handshakeMessages.add(message.toBytes())

        state = HandshakeState.SERVER_HELLO_SENT

        return message
    }

    /**
     * Step 3: CLIENT - Process ServerHello and generate ClientKeyExchange
     */
    fun generateClientKeyExchange(
        serverHello: ServerHelloMessage
    ): ClientKeyExchangeMessage {
        require(state == HandshakeState.CLIENT_HELLO_SENT) { "Invalid state" }

        // Record server hello
        handshakeMessages.add(serverHello.toBytes())

        // Verify server certificate
        require(certManager.verifyCertificate(serverHello.certificate)) {
            "Server certificate verification failed"
        }

        // Store server's DH public key
        peerDHPublicKey = serverHello.dhPublicKey
        serverRandom = serverHello.serverRandom

        // Generate our DH key pair
        myDHPrivateKey = dh.generatePrivateKey(dhParameters!!)
        myDHPublicKey = dh.generatePublicKey(myDHPrivateKey!!, dhParameters!!)

        // Compute Pre-Master Secret (DH shared secret)
        preMasterSecret = dh.computeSharedSecret(
            myDHPrivateKey!!,
            peerDHPublicKey!!,
            dhParameters!!
        )

        // Derive Master Secret
        masterSecret = kdf.deriveMasterSecret(
            preMasterSecret!!.toByteArray(),
            clientRandom!!,
            serverRandom!!
        )

        // Derive Session Keys
        sessionKeys = kdf.deriveSessionKeys(
            masterSecret!!,
            clientRandom!!,
            serverRandom!!
        )

        // Generate our certificate
        val certificate = certManager.generateSelfSignedCertificate(
            myPhoneNumber,
            myKeyPair
        )

        // Sign DH public key for authentication
        val dhPubKeyHash = sha256.hash(myDHPublicKey!!.toByteArray())
        val signature = rsa.sign(BigInteger(1, dhPubKeyHash), myKeyPair.privateKey)

        val message = ClientKeyExchangeMessage(
            certificate = certificate,
            dhPublicKey = myDHPublicKey!!,
            signature = signature.toByteArray()
        )

        handshakeMessages.add(message.toBytes())
        state = HandshakeState.CLIENT_KEY_EXCHANGE_SENT

        return message
    }

    /**
     * Step 4: SERVER - Process ClientKeyExchange
     */
    fun processClientKeyExchange(clientKeyExchange: ClientKeyExchangeMessage) {
        require(state == HandshakeState.SERVER_HELLO_SENT) { "Invalid state" }

        // Record message
        handshakeMessages.add(clientKeyExchange.toBytes())

        // Verify client certificate
        require(certManager.verifyCertificate(clientKeyExchange.certificate)) {
            "Client certificate verification failed"
        }

        // Verify signature on DH public key
        val dhPubKeyHash = sha256.hash(clientKeyExchange.dhPublicKey.toByteArray())
        require(rsa.verify(
            BigInteger(1, dhPubKeyHash),
            BigInteger(1, clientKeyExchange.signature),
            clientKeyExchange.certificate.publicKey
        )) {
            "DH public key signature verification failed"
        }

        // Store peer's DH public key
        peerDHPublicKey = clientKeyExchange.dhPublicKey

        // Compute Pre-Master Secret
        preMasterSecret = dh.computeSharedSecret(
            myDHPrivateKey!!,
            peerDHPublicKey!!,
            dhParameters!!
        )

        // Derive Master Secret
        masterSecret = kdf.deriveMasterSecret(
            preMasterSecret!!.toByteArray(),
            clientRandom!!,
            serverRandom!!
        )

        // Derive Session Keys
        sessionKeys = kdf.deriveSessionKeys(
            masterSecret!!,
            clientRandom!!,
            serverRandom!!
        )

        state = HandshakeState.KEYS_DERIVED
    }

    /**
     * Step 5: Generate Finished message
     * Contains HMAC of all handshake messages
     */
    fun generateFinished(isClient: Boolean): FinishedMessage {
        require(state == HandshakeState.CLIENT_KEY_EXCHANGE_SENT ||
                state == HandshakeState.KEYS_DERIVED) { "Invalid state" }

        // Concatenate all handshake messages
        val allMessages = handshakeMessages.fold(ByteArray(0)) { acc, msg -> acc + msg }

        // Select appropriate MAC key
        val macKey = if (isClient) {
            sessionKeys!!.clientMacKey
        } else {
            sessionKeys!!.serverMacKey
        }

        // Compute HMAC
        val verifyData = hmac.compute(macKey, allMessages)

        val message = FinishedMessage(verifyData)

        state = HandshakeState.FINISHED_SENT

        return message
    }

    /**
     * Step 6: Verify Finished message from peer
     */
    fun verifyFinished(finished: FinishedMessage, isClient: Boolean): Boolean {
        // Concatenate all handshake messages
        val allMessages = handshakeMessages.fold(ByteArray(0)) { acc, msg -> acc + msg }

        // Select appropriate MAC key (opposite of sender)
        val macKey = if (!isClient) {
            sessionKeys!!.clientMacKey
        } else {
            sessionKeys!!.serverMacKey
        }

        // Verify HMAC
        val valid = hmac.verify(macKey, allMessages, finished.verifyData)

        if (valid) {
            state = HandshakeState.ESTABLISHED
        }

        return valid
    }

    /**
     * Get the established session keys
     */
    fun getSessionKeys(): SessionKeys {
        require(state == HandshakeState.ESTABLISHED) { "Handshake not complete" }
        return sessionKeys!!
    }
}