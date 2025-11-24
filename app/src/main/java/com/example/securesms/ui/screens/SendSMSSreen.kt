// File: app/src/main/java/com/example/securesms/ui/screens/SendSMSSreen.kt
package com.example.securesms.ui.screens

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.RequiresApi
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Send
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.example.securesms.crypto.asymmetric.RSA
import com.example.securesms.crypto.models.RSAKeyPair
import com.example.securesms.sms.SMSManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@RequiresApi(Build.VERSION_CODES.TIRAMISU)
@Composable
fun SendSMSScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val smsManager = remember { SMSManager(context) }

    var peerPhone by remember { mutableStateOf("") }
    var messageText by remember { mutableStateOf("") }
    var logs by remember { mutableStateOf(listOf<String>()) }
    var keyPair by remember { mutableStateOf<RSAKeyPair?>(null) }
    var isHandshaking by remember { mutableStateOf(false) }

    // Permission launcher
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val granted = permissions.entries.all { it.value }
        if (granted) logs = logs + "SMS Permissions Granted"
    }

    LaunchedEffect(Unit) {
        permissionLauncher.launch(arrayOf(Manifest.permission.SEND_SMS, Manifest.permission.RECEIVE_SMS))
        // Generate Identity Key on load
        withContext(Dispatchers.Default) {
            keyPair = RSA.generateKeyPair(2048)
        }
        logs = logs + "Identity Key Generated (RSA 2048-bit)"
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("Secure SMS Channel", style = MaterialTheme.typography.headlineMedium)

        Spacer(modifier = Modifier.height(16.dp))

        OutlinedTextField(
            value = peerPhone,
            onValueChange = { peerPhone = it },
            label = { Text("Recipient Phone Number") },
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(8.dp))

        Button(
            onClick = {
                if (keyPair != null && peerPhone.isNotEmpty()) {
                    isHandshaking = true
                    logs = logs + "Starting Handshake with $peerPhone..."

                    scope.launch(Dispatchers.IO) {
                        try {
                            // Note: In a real app, this initiates the flow.
                            // The receiving, parsing, and state updates happen via SMSReceiver.
                            smsManager.initiateHandshake(peerPhone, "MyPhone", keyPair!!)
                            withContext(Dispatchers.Main) {
                                logs = logs + ">> ClientHello Sent (Waiting for reply...)"
                                isHandshaking = false
                            }
                        } catch (e: Exception) {
                            withContext(Dispatchers.Main) {
                                logs = logs + "Error: ${e.message}"
                            }
                        }
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isHandshaking
        ) {
            Icon(Icons.Default.Lock, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text("Initiate TLS Handshake")
        }

        Spacer(modifier = Modifier.height(16.dp))

        OutlinedTextField(
            value = messageText,
            onValueChange = { messageText = it },
            label = { Text("Secure Message") },
            modifier = Modifier.fillMaxWidth(),
            maxLines = 3
        )

        Button(
            onClick = {
                logs = logs + "Encrypting and sending..."
                val result = smsManager.sendEncryptedMessage(peerPhone, messageText)
                logs = logs + ">> $result"
                messageText = ""
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = peerPhone.isNotEmpty()
        ) {
            Icon(Icons.Default.Send, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text("Send Encrypted")
        }

        Spacer(modifier = Modifier.height(16.dp))
        Text("Protocol Logs:", style = MaterialTheme.typography.labelLarge)

        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .background(MaterialTheme.colorScheme.surfaceVariant)
                .padding(8.dp)
        ) {
            items(logs) { log ->
                Text(text = log, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}