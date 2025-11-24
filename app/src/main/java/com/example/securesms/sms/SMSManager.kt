// File: app/src/main/java/com/example/securesms/sms/SMSManager.kt
package com.example.securesms.sms

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.SmsManager
import android.util.Base64
import androidx.annotation.RequiresApi
import androidx.core.app.ActivityCompat
import com.example.securesms.crypto.handshake.*
import com.example.securesms.crypto.models.RSAKeyPair
import com.example.securesms.crypto.models.RSAPrivateKey
import com.example.securesms.crypto.models.RSAPublicKey
import com.example.securesms.crypto.symmetric.AES

@RequiresApi(Build.VERSION_CODES.TIRAMISU)
class SMSManager(private val context: Context) {

    // In a real app, use Dependency Injection. For this demo, we use a static map.
    companion object {
        val handshakes = mutableMapOf<String, TLSHandshake>()
        // Mocking a consistent Identity Key for the "User" for this session
        var myIdentityKey: RSAKeyPair? = null
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

    // Simulate receiving a message (Since we can't really receive on one device easily)
    // In production, this would be called by SMSReceiver
    fun onReceiveMessage(sender: String, body: String) {
        val parts = body.split(":", limit = 2)
        if (parts.size < 2) return

        val type = parts[0]
        val payload = parts[1]

        // Retrieve or create handshake state
        var handshake = handshakes[sender]
        if (handshake == null && myIdentityKey != null) {
            handshake = TLSHandshake(sender, myIdentityKey!!) // Using sender as 'my' phone for symmetry in this mock
            handshakes[sender] = handshake
        }

        if (handshake == null) return // Can't process without init

        try {
            when (type) {
                "CL_HELLO" -> {
                    val msg = ClientHelloMessage.fromString(payload)
                    val response = handshake.handleClientHello(msg)
                    sendRawSMS(sender, "SV_HELLO:${response}")
                }
                "SV_HELLO" -> {
                    // Reconstruct objects from string (simplified parsing for demo)
                    // In real app, proper serialization needed.
                    // For this demo, we assume the UI drives the flow linearly.
                }
                // ... handling other states
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun sendEncryptedMessage(peerPhone: String, message: String): String {
        val handshake = handshakes[peerPhone] ?: return "Error: No handshake"
        val keys = handshake.sessionKeys ?: return "Error: Not established"

        val aes = AES()
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
}