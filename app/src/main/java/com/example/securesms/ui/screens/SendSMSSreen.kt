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
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.ui.unit.sp
import com.example.securesms.crypto.asymmetric.RSA
import com.example.securesms.crypto.models.RSAKeyPair
import com.example.securesms.sms.ChatMessage
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

    var peerPhone by remember { mutableStateOf("5556") } // Default for 5554
    var messageText by remember { mutableStateOf("") }

    // Observe Data
    val logs by SMSManager.logState.collectAsState()
    val messages by SMSManager.messageState.collectAsState()

    var keyPair by remember { mutableStateOf<RSAKeyPair?>(null) }
    var isKeyReady by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()

    // Permission launcher
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { }

    LaunchedEffect(Unit) {
        permissionLauncher.launch(arrayOf(Manifest.permission.SEND_SMS, Manifest.permission.RECEIVE_SMS))
        withContext(Dispatchers.Default) {
            if (SMSManager.myIdentityKey == null) {
                keyPair = RSA.generateKeyPair(2048)
                SMSManager.myIdentityKey = keyPair
            } else {
                keyPair = SMSManager.myIdentityKey
            }
        }
        isKeyReady = true
    }

    // Auto-scroll to bottom of chat
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    Column(modifier = Modifier.fillMaxSize().background(Color(0xFFF5F5F5))) {

        // --- Header ---
        Surface(shadowElevation = 4.dp, color = MaterialTheme.colorScheme.primaryContainer) {
            Column(modifier = Modifier.padding(16.dp).fillMaxWidth()) {
                Text("Secure SMS", style = MaterialTheme.typography.titleLarge)
                Spacer(modifier = Modifier.height(8.dp))

                // Recipient Input & Handshake
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = peerPhone,
                        onValueChange = { peerPhone = it },
                        label = { Text("Target Port (e.g. 5556)") },
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(
                        onClick = {
                            scope.launch(Dispatchers.IO) {
                                if (keyPair != null) smsManager.initiateHandshake(peerPhone, "MyPhone", keyPair!!)
                            }
                        },
                        enabled = isKeyReady
                    ) {
                        Icon(Icons.Default.Lock, contentDescription = null)
                    }
                }
            }
        }

        // --- Chat Area (Bubbles) ---
        LazyColumn(
            state = listState,
            modifier = Modifier.weight(1f).fillMaxWidth().padding(horizontal = 16.dp),
            contentPadding = PaddingValues(vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(messages) { msg ->
                ChatBubble(msg)
            }
        }

        // --- Protocol Logs (Collapsible/Bottom) ---
        Divider()
        Text("Protocol Logs:", style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(8.dp))
        LazyColumn(
            modifier = Modifier.height(100.dp).fillMaxWidth().background(Color.Black).padding(8.dp)
        ) {
            items(logs.takeLast(20)) { log -> // Only show last 20 logs
                Text(text = log, color = Color.Green, fontSize = 10.sp, lineHeight = 12.sp)
            }
        }

        // --- Input Area ---
        Surface(tonalElevation = 2.dp) {
            Row(modifier = Modifier.padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = messageText,
                    onValueChange = { messageText = it },
                    placeholder = { Text("Type encrypted message...") },
                    modifier = Modifier.weight(1f)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Button(
                    onClick = {
                        if (messageText.isNotEmpty()) {
                            smsManager.sendEncryptedMessage(peerPhone, messageText)
                            messageText = ""
                        }
                    }
                ) {
                    Icon(Icons.Default.Send, contentDescription = null)
                }
            }
        }
    }
}

@Composable
fun ChatBubble(message: ChatMessage) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = if (message.isFromMe) Alignment.End else Alignment.Start
    ) {
        Surface(
            color = if (message.isFromMe) MaterialTheme.colorScheme.primary else Color.LightGray,
            shape = RoundedCornerShape(16.dp),
            shadowElevation = 2.dp
        ) {
            Text(
                text = message.content,
                modifier = Modifier.padding(12.dp),
                color = if (message.isFromMe) Color.White else Color.Black
            )
        }
    }
}