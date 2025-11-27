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
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.securesms.crypto.asymmetric.RSAAuthProvider
import com.example.securesms.crypto.asymmetric.ECDSAAuthProvider
import com.example.securesms.sms.ChatMessage
import com.example.securesms.sms.SMSManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import AuthenticationProvider

@RequiresApi(Build.VERSION_CODES.TIRAMISU)
@Composable
fun SendSMSScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val smsManager = remember { SMSManager(context) }

    var myPhone by remember { mutableStateOf("5556") } // Default emulator port
    var peerPhone by remember { mutableStateOf("5554") } // Default target
    var messageText by remember { mutableStateOf("") }

    // Algorithm selection
    var useECDSA by remember { mutableStateOf(true) } // Default to ECDSA
    var isInitialized by remember { mutableStateOf(false) }
    var showAlgorithmDialog by remember { mutableStateOf(false) }

    // Observe Data
    val logs by SMSManager.logState.collectAsState()
    val messages by SMSManager.messageState.collectAsState()
    val listState = rememberLazyListState()

    // Permission launcher
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { }

    // Initialize authentication on startup
    LaunchedEffect(Unit) {
        permissionLauncher.launch(
            arrayOf(
                Manifest.permission.SEND_SMS,
                Manifest.permission.RECEIVE_SMS
            )
        )

        // Initialize with default algorithm if not already done
        if (SMSManager.authProvider == null) {
            withContext(Dispatchers.Default) {
                val authProvider = if (useECDSA) {
                    ECDSAAuthProvider(ECDSAAuthProvider.CurveType.P256)
                } else {
                    RSAAuthProvider(2048)
                }
                smsManager.initializeAuth(myPhone, authProvider)
            }
            isInitialized = true
        } else {
            isInitialized = true
        }
    }

    // Auto-scroll to bottom of chat
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    // Algorithm selection dialog
    if (showAlgorithmDialog) {
        AlgorithmSelectionDialog(
            currentUseECDSA = useECDSA,
            onDismiss = { showAlgorithmDialog = false },
            onConfirm = { newUseECDSA ->
                useECDSA = newUseECDSA
                scope.launch(Dispatchers.Default) {
                    // Clear existing handshakes
                    SMSManager.handshakes.clear()

                    // Reinitialize with new algorithm
                    val authProvider = if (newUseECDSA) {
                        ECDSAAuthProvider(ECDSAAuthProvider.CurveType.P256)
                    } else {
                        RSAAuthProvider(2048)
                    }
                    smsManager.initializeAuth(myPhone, authProvider)
                }
                showAlgorithmDialog = false
            }
        )
    }

    Column(modifier = Modifier.fillMaxSize().background(Color(0xFFF5F5F5))) {

        // --- Header ---
        Surface(shadowElevation = 4.dp, color = MaterialTheme.colorScheme.primaryContainer) {
            Column(modifier = Modifier.padding(16.dp).fillMaxWidth()) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text("Secure SMS", style = MaterialTheme.typography.titleLarge)
                        Text(
                            text = "Algorithm: ${SMSManager.authProvider?.algorithm ?: "Not initialized"}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                        )
                    }
                    IconButton(onClick = { showAlgorithmDialog = true }) {
                        Icon(Icons.Default.Settings, contentDescription = "Change Algorithm")
                    }
                }

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
                                smsManager.initiateHandshake(peerPhone)
                            }
                        },
                        enabled = isInitialized
                    ) {
                        Icon(Icons.Default.Lock, contentDescription = "Initiate Handshake")
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Handshake")
                    }
                }
            }
        }

        // --- Chat Area (Bubbles) ---
        LazyColumn(
            state = listState,
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            contentPadding = PaddingValues(vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(messages) { msg ->
                ChatBubble(msg)
            }
        }

        // --- Protocol Logs (Collapsible/Bottom) ---
        Divider()
        Text(
            "Protocol Logs:",
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(8.dp)
        )
        LazyColumn(
            modifier = Modifier
                .height(100.dp)
                .fillMaxWidth()
                .background(Color.Black)
                .padding(8.dp)
        ) {
            items(logs.takeLast(20)) { log ->
                Text(
                    text = log,
                    color = Color.Green,
                    fontSize = 10.sp,
                    lineHeight = 12.sp
                )
            }
        }

        // --- Input Area ---
        Surface(tonalElevation = 2.dp) {
            Row(
                modifier = Modifier.padding(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
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
                    },
                    enabled = isInitialized
                ) {
                    Icon(Icons.Default.Send, contentDescription = "Send Message")
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
            color = if (message.isFromMe) {
                MaterialTheme.colorScheme.primary
            } else {
                Color.LightGray
            },
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

@Composable
fun AlgorithmSelectionDialog(
    currentUseECDSA: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (Boolean) -> Unit
) {
    var selectedUseECDSA by remember { mutableStateOf(currentUseECDSA) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Select Authentication Algorithm") },
        text = {
            Column {
                Text(
                    "Choose the algorithm for authentication:",
                    style = MaterialTheme.typography.bodyMedium
                )
                Spacer(modifier = Modifier.height(16.dp))

                // ECDSA Option
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RadioButton(
                        selected = selectedUseECDSA,
                        onClick = { selectedUseECDSA = true }
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Column {
                        Text(
                            "ECDSA-P256 (Recommended)",
                            style = MaterialTheme.typography.bodyLarge
                        )
                        Text(
                            "Fast, small signatures, 128-bit security",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color.Gray
                        )
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                // RSA Option
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RadioButton(
                        selected = !selectedUseECDSA,
                        onClick = { selectedUseECDSA = false }
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Column {
                        Text(
                            "RSA-2048",
                            style = MaterialTheme.typography.bodyLarge
                        )
                        Text(
                            "Traditional, larger signatures, 112-bit security",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color.Gray
                        )
                    }
                }

                if (selectedUseECDSA != currentUseECDSA) {
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        "⚠️ Changing algorithm will clear all handshakes",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        },
        confirmButton = {
            Button(onClick = { onConfirm(selectedUseECDSA) }) {
                Text("Apply")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}