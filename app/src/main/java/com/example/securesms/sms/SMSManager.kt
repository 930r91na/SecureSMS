package com.example.securesms.sms

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.SmsManager
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.core.app.ActivityCompat
import com.example.securesms.crypto.handshake.*
import com.example.securesms.crypto.symmetric.AES
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import AuthenticationProvider

@RequiresApi(Build.VERSION_CODES.TIRAMISU)
class SMSManager(private val context: Context) {

    companion object {
        // Store handshakes per peer phone number
        val handshakes = mutableMapOf<String, TLSHandshake>()

        // Store the authentication provider (RSA or ECDSA)
        var authProvider: AuthenticationProvider? = null

        // My phone number
        var myPhoneNumber: String? = null

        private val _logState = MutableStateFlow(listOf<String>())
        val logState = _logState.asStateFlow()

        private val _messageState = MutableStateFlow(listOf<ChatMessage>())
        val messageState = _messageState.asStateFlow()

        fun addMessage(msg: ChatMessage) {
            val current = _messageState.value.toMutableList()
            current.add(msg)
            _messageState.value = current
        }

        fun appendLog(msg: String) {
            Log.d("SecureSMS_Protocol", msg)
            val current = _logState.value.toMutableList()
            current.add(msg)
            _logState.value = current
        }
    }

    private fun getSmsManager(): SmsManager {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            context.getSystemService(SmsManager::class.java)
        } else {
            SmsManager.getDefault()
        }
    }

    /**
     * Initialize the authentication provider
     * Call this once at app startup with your chosen algorithm
     *
     * Example:
     *   val rsaAuth = RSAAuthProvider(2048)
     *   smsManager.initializeAuth("1234567890", rsaAuth)
     *
     * Or with ECDSA:
     *   val ecdsaAuth = ECDSAAuthProvider(ECDSAAuthProvider.CurveType.P256)
     *   smsManager.initializeAuth("1234567890", ecdsaAuth)
     */
    fun initializeAuth(myPhone: String, provider: AuthenticationProvider) {
        myPhoneNumber = myPhone
        authProvider = provider
        appendLog("Initialized with ${provider.algorithm}")
    }

    /**
     * Initiate handshake with peer
     * @param peerPhone Peer's phone number
     */
    fun initiateHandshake(peerPhone: String) {
        // Check if initialized
        if (authProvider == null || myPhoneNumber == null) {
            appendLog("Error: Call initializeAuth() first!")
            return
        }

        // Create new handshake with the authentication provider
        val handshake = TLSHandshake(myPhoneNumber!!, authProvider!!)
        handshakes[peerPhone] = handshake

        // Generate and send ClientHello
        val hello = handshake.generateClientHello()
        sendRawSMS(peerPhone, "CL_HELLO:${hello}")
        appendLog(">> ClientHello sent to $peerPhone")
    }

    fun onReceiveMessage(sender: String, body: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                appendLog("<< SMS Received from $sender")
                Log.d("SecureSMS_Protocol", "Processing message on background thread...")

                // Check if authentication is initialized
                if (authProvider == null || myPhoneNumber == null) {
                    appendLog("Error: Authentication not initialized. Call initializeAuth() first!")
                    return@launch
                }

                // Retrieve or create handshake state
                var handshake = handshakes[sender]

                if (handshake == null) {
                    Log.d("SecureSMS_Protocol", "Creating new handshake session for $sender")
                    handshake = TLSHandshake(myPhoneNumber!!, authProvider!!)
                    handshakes[sender] = handshake
                }

                // Parse Message
                val parts = body.split(":", limit = 2)
                if (parts.size < 2) {
                    appendLog("Ignored: Unknown format (no colon)")
                    return@launch
                }

                // Remove whitespace that can break parsing
                val type = parts[0].trim()
                val payload = parts[1].trim()

                Log.d("SecureSMS_Protocol", "Message Type: '$type'")

                when (type) {
                    "CL_HELLO" -> {
                        appendLog("Processing ClientHello...")
                        appendLog("Generating ServerHello (Crypto Heavy)...")
                        val msg = ClientHelloMessage.fromString(payload)
                        val response = handshake.handleClientHello(msg)
                        sendRawSMS(sender, "SV_HELLO:${response}")
                        appendLog(">> ServerHello Sent")
                    }

                    "SV_HELLO" -> {
                        appendLog("Processing ServerHello...")
                        val msg = ServerHelloMessage.fromString(payload)
                        val response = handshake.handleServerHello(msg)
                        sendRawSMS(sender, "CL_KEY_EX:${response}")
                        appendLog(">> ClientKeyExchange Sent")
                    }

                    "CL_KEY_EX" -> {
                        appendLog("Processing ClientKeyExchange...")
                        val msg = ClientKeyExchangeMessage.fromString(payload)
                        handshake.handleClientKeyExchange(msg)
                        appendLog("✅ SECURE HANDSHAKE COMPLETE!")
                        appendLog("Algorithm: ${handshake.getAuthAlgorithm()}")
                    }

                    "MSG" -> {
                        // Handle Encrypted Message
                        val keys = handshake.sessionKeys
                        if (keys != null) {
                            val data = Base64.decode(payload, Base64.NO_WRAP)
                            val aes = AES()

                            // Try server key first (if we're the client)
                            try {
                                val key = AES.keyFromBytes(keys.serverEncryptKey)
                                val encryptedObj = AES.EncryptedMessage.fromBytes(data)
                                val plain = aes.decryptToString(encryptedObj, key)
                                addMessage(ChatMessage(plain, isFromMe = false))
                                appendLog("<< Decrypted: $plain")
                                showToast("Decrypted from $sender: $plain")
                            } catch (e: Exception) {
                                // Try client key if server key fails
                                try {
                                    val key2 = AES.keyFromBytes(keys.clientEncryptKey)
                                    val encryptedObj = AES.EncryptedMessage.fromBytes(data)
                                    val plain = aes.decryptToString(encryptedObj, key2)
                                    addMessage(ChatMessage(plain, isFromMe = false))
                                    appendLog("<< Decrypted: $plain")
                                    showToast("Decrypted from $sender: $plain")
                                } catch (e2: Exception) {
                                    appendLog("Error: Failed to decrypt message")
                                    Log.e("SecureSMS_Protocol", "Decryption failed", e2)
                                }
                            }
                        } else {
                            appendLog("Error: No session keys available")
                        }
                    }

                    else -> {
                        appendLog("Error: Unknown message type '$type'")
                    }
                }
            } catch (e: Exception) {
                e.printStackTrace()
                appendLog("Error: ${e.message}")
                Log.e("SecureSMS_Protocol", "Crash in receiver", e)
            }
        }
    }

    fun sendEncryptedMessage(peerPhone: String, message: String): String {
        val handshake = handshakes[peerPhone] ?: return "Error: No handshake with $peerPhone"
        val keys = handshake.sessionKeys ?: return "Error: Handshake not complete"

        val aes = AES()
        // Client uses clientEncryptKey to encrypt
        val key = AES.keyFromBytes(keys.clientEncryptKey)
        val encrypted = aes.encrypt(message, key)

        addMessage(ChatMessage(message, isFromMe = true))

        val payload = Base64.encodeToString(encrypted.toBytes(), Base64.NO_WRAP)
        sendRawSMS(peerPhone, "MSG:$payload")
        appendLog(">> Encrypted message sent")

        return "Sent"
    }

    private fun sendRawSMS(phone: String, text: String) {
        // 1. Log the "Cheat Code" for manual relay
        Log.e("SecureSMS_Manual", ">>> RUN THIS COMMAND TO DELIVER MESSAGE:")
        Log.e("SecureSMS_Manual", "adb -s emulator-$phone emu sms send ${myPhoneNumber ?: "1234"} \"$text\"")
        Log.e("SecureSMS_Manual", "")

        // 2. Attempt real sending
        if (ActivityCompat.checkSelfPermission(context, Manifest.permission.SEND_SMS) != PackageManager.PERMISSION_GRANTED) {
            appendLog("Error: Send Permission missing")
            return
        }

        try {
            val smsManager = getSmsManager()
            val parts = smsManager.divideMessage(text)
            smsManager.sendMultipartTextMessage(phone, null, parts, null, null)
            appendLog(">> Message sent to network")
        } catch (e: Exception) {
            appendLog("Error sending SMS: ${e.message}")
            Log.e("SecureSMS_Protocol", "SMS send error", e)
        }
    }

    private fun showToast(msg: String) {
        // Must run on main thread
        android.os.Handler(android.os.Looper.getMainLooper()).post {
            Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
        }
    }
}