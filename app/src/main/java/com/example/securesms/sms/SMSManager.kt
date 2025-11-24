package com.example.securesms.sms

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.telephony.SmsManager
import android.util.Base64
import androidx.core.content.ContextCompat
//import com.example.securesms.crypto.handshake.TLSHandshake
import com.example.securesms.crypto.models.*

class SMSManager(private val context: Context) {

    private val smsManager = SmsManager.getDefault()

    // Active handshakes: phoneNumber -> TLSHandshake
    //private val activeHandshakes = mutableMapOf<String, TLSHandshake>()

    // Established sessions: phoneNumber -> SessionKeys
    private val establishedSessions = mutableMapOf<String, SessionKeys>()

    /**
     * Initiate handshake with peer
     */
    fun initiateHandshake(
        peerPhone: String,
        myPhone: String,
        myKeyPair: RSAKeyPair
    ) {
        //val handshake = TLSHandshake(myPhone, myKeyPair)
        //activeHandshakes[peerPhone] = handshake

        // Generate ClientHello
        //val clientHello = handshake.generateClientHello()

        // Send via SMS
        //sendHandshakeMessage(peerPhone, "CLIENT_HELLO", clientHello.toBytes())
    }

    /**
     * Send encrypted message (after handshake)
     */
    fun sendEncryptedMessage(
        peerPhone: String,
        message: String
    ): Boolean {
        val sessionKeys = establishedSessions[peerPhone]
            ?: return false // No session established

        // Encrypt with AES-GCM
        val aes = com.example.securesms.crypto.symmetric.AES()
        val encryptedData = aes.encryptString(
            message,
            javax.crypto.spec.SecretKeySpec(sessionKeys.clientEncryptKey, "AES")
        )

        // Compute HMAC
        val hmac = com.example.securesms.crypto.hash.HMAC()
        val mac = hmac.compute(sessionKeys.clientMacKey, encryptedData)

        // Package: [Encrypted Data][HMAC]
        val payload = encryptedData + mac

        // Encode and send
        return sendSMS(peerPhone, "DATA", payload)
    }

    private fun sendHandshakeMessage(
        peerPhone: String,
        type: String,
        data: ByteArray
    ) {
        sendSMS(peerPhone, type, data)
    }

    private fun sendSMS(
        phoneNumber: String,
        messageType: String,
        data: ByteArray
    ): Boolean {
        if (!hasPermission()) return false

        try {
            // Format: TYPE:BASE64_DATA
            val encoded = Base64.encodeToString(data, Base64.NO_WRAP)
            val fullMessage = "$messageType:$encoded"

            // Send (handle multipart if needed)
            val parts = smsManager.divideMessage(fullMessage)
            if (parts.size == 1) {
                smsManager.sendTextMessage(phoneNumber, null, fullMessage, null, null)
            } else {
                smsManager.sendMultipartTextMessage(phoneNumber, null, parts, null, null)
            }

            return true
        } catch (e: Exception) {
            e.printStackTrace()
            return false
        }
    }

    private fun hasPermission(): Boolean {
        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.SEND_SMS
        ) == PackageManager.PERMISSION_GRANTED
    }
}