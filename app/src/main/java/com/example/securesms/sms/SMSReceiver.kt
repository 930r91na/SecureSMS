package com.example.securesms.sms

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.telephony.SmsMessage
import android.util.Log
import androidx.annotation.RequiresApi

class SMSReceiver : BroadcastReceiver() {
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == "android.provider.Telephony.SMS_RECEIVED") {
            val bundle = intent.extras
            val pdus = bundle?.get("pdus") as? Array<*>
            val format = bundle?.getString("format")

            if (pdus != null) {
                // FIXED: Use StringBuilder to stitch multipart messages back together
                val fullMessage = StringBuilder()
                var sender = ""

                for (pdu in pdus) {
                    val sms = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        SmsMessage.createFromPdu(pdu as ByteArray, format)
                    } else {
                        SmsMessage.createFromPdu(pdu as ByteArray)
                    }

                    fullMessage.append(sms.messageBody)
                    sender = sms.displayOriginatingAddress ?: sender
                }

                val finalBody = fullMessage.toString()
                Log.d("SecureSMS", "Reassembled SMS from $sender: $finalBody")

                // Forward the COMPLETE message to SMSManager
                val smsManager = SMSManager(context)
                smsManager.onReceiveMessage(sender, finalBody)
            }
        }
    }
}