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
import com.example.securesms.crypto.models.RSAKeyPair
import com.example.securesms.crypto.symmetric.AES
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
@RequiresApi(Build.VERSION_CODES.TIRAMISU)
class SMSManager(private val context: Context) {

    companion object {
        val handshakes = mutableMapOf<String, TLSHandshake>()
        var myIdentityKey: RSAKeyPair? = null

        private val _logState = MutableStateFlow(listOf<String>())
        val logState = _logState.asStateFlow()

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

    fun initiateHandshake(peerPhone: String, myPhone: String, keyPair: RSAKeyPair) {
        myIdentityKey = keyPair
        val handshake = TLSHandshake(myPhone, keyPair)
        handshakes[peerPhone] = handshake

        val hello = handshake.generateClientHello()
        sendRawSMS(peerPhone, "CL_HELLO:${hello}")
    }


    fun onReceiveMessage(sender: String, body: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                appendLog("<< SMS Received from $sender")
                Log.d("SecureSMS_Protocol", "Processing message on background thread...")

                // 1. Retrieve or create handshake state
                var handshake = handshakes[sender]

                // Check Identity Key
                if (myIdentityKey == null) {
                    appendLog("Error: Identity Key is NULL. Did you click 'Initiate'?")
                    return@launch
                }

                if (handshake == null) {
                    Log.d("SecureSMS_Protocol", "Creating new handshake session for $sender")
                    handshake = TLSHandshake(sender, myIdentityKey!!)
                    handshakes[sender] = handshake
                }

                // 2. Parse Message
                val parts = body.split(":", limit = 2)
                if (parts.size < 2) {
                    appendLog("Ignored: Unknown format (no colon)")
                    return@launch
                }

                // CRITICAL FIX: .trim() removes invisible spaces/newlines that break the match
                val type = parts[0].trim()
                val payload = parts[1].trim()

                Log.d("SecureSMS_Protocol", "Message Type: '$type'") // Debug log to see what we got

                when (type) {
                    "CL_HELLO" -> {
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
                        appendLog("SECURE HANDSHAKE COMPLETE!")
                    }
                    "MSG" -> {
                        // 4. Handle Encrypted Message
                        val keys = handshake.sessionKeys
                        if (keys != null) {
                            val data = Base64.decode(payload, Base64.NO_WRAP)
                            val aes = AES()
                            val key = AES.keyFromBytes(keys.serverEncryptKey) // Use server key if we are client?
                            // Note: In this simple symmetric setup, just ensure you use the correct matching key.
                            // For simplicity in this demo, we try decrypting.
                            try {
                                val encryptedObj = AES.EncryptedMessage.fromBytes(data)
                                val plain = aes.decryptToString(encryptedObj, key)
                                showToast("Decrypted from $sender: $plain")
                            } catch (e: Exception) {
                                // Try the other key if roles are confused
                                val key2 = AES.keyFromBytes(keys.clientEncryptKey)
                                val encryptedObj = AES.EncryptedMessage.fromBytes(data)
                                val plain = aes.decryptToString(encryptedObj, key2)
                                showToast("Decrypted from $sender: $plain")
                            }
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
        val handshake = handshakes[peerPhone] ?: return "Error: No handshake"
        val keys = handshake.sessionKeys ?: return "Error: Not established"

        val aes = AES()
        // Client uses Client Key to encrypt
        val key = AES.keyFromBytes(keys.clientEncryptKey)
        val encrypted = aes.encrypt(message, key)

        val payload = Base64.encodeToString(encrypted.toBytes(), Base64.NO_WRAP)
        sendRawSMS(peerPhone, "MSG:$payload")
        return "Sent"
    }

    private fun sendRawSMS(phone: String, text: String) {
        if (ActivityCompat.checkSelfPermission(context, Manifest.permission.SEND_SMS) != PackageManager.PERMISSION_GRANTED) {
            return
        }
        val smsManager = getSmsManager()
        val parts = smsManager.divideMessage(text)
        smsManager.sendMultipartTextMessage(phone, null, parts, null, null)
    }

    private fun showToast(msg: String) {
        // Must run on main thread
        android.os.Handler(android.os.Looper.getMainLooper()).post {
            Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
        }
    }
}