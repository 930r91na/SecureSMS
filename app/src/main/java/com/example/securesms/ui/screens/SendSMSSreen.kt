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

    var useECDSA by remember { mutableStateOf(true) } // Default to ECDSA
    var rsaKeySize by remember { mutableStateOf(2048) } // RSA key size
    var ecdsaCurve by remember { mutableStateOf(ECDSAAuthProvider.CurveType.P256) } // ECDSA curve
    var isInitialized by remember { mutableStateOf(false) }
    var showAlgorithmDialog by remember { mutableStateOf(false) }

    val logs by SMSManager.logState.collectAsState()
    val messages by SMSManager.messageState.collectAsState()
    val listState = rememberLazyListState()
    val logListState = rememberLazyListState()

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
                    ECDSAAuthProvider(ecdsaCurve)
                } else {
                    RSAAuthProvider(rsaKeySize)
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

    // Auto-scroll to bottom of logs
    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) {
            logListState.animateScrollToItem(maxOf(0, logs.takeLast(20).size - 1))
        }
    }

    // Algorithm selection dialog
    if (showAlgorithmDialog) {
        AlgorithmSelectionDialog(
            currentUseECDSA = useECDSA,
            currentRSAKeySize = rsaKeySize,
            currentECDSACurve = ecdsaCurve,
            onDismiss = { showAlgorithmDialog = false },
            onConfirm = { newUseECDSA, newRSAKeySize, newECDSACurve ->
                useECDSA = newUseECDSA
                rsaKeySize = newRSAKeySize
                ecdsaCurve = newECDSACurve

                scope.launch(Dispatchers.Default) {
                    // Clear existing handshakes
                    SMSManager.handshakes.clear()

                    // Reinitialize with new algorithm
                    val authProvider = if (newUseECDSA) {
                        ECDSAAuthProvider(newECDSACurve)
                    } else {
                        RSAAuthProvider(newRSAKeySize)
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
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
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

                        Spacer(modifier = Modifier.height(8.dp))

                        Button(
                            onClick = {
                                SMSManager.handshakes.clear()
                                SMSManager.appendLog("Cleared all handshakes - fresh certificates will be generated")
                            }
                        ) {
                            Text("Clear Handshakes")
                        }
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
            state = logListState,
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

@RequiresApi(Build.VERSION_CODES.TIRAMISU)
@Composable
fun AlgorithmSelectionDialog(
    currentUseECDSA: Boolean,
    currentRSAKeySize: Int,
    currentECDSACurve: ECDSAAuthProvider.CurveType,
    onDismiss: () -> Unit,
    onConfirm: (Boolean, Int, ECDSAAuthProvider.CurveType) -> Unit
) {
    var selectedUseECDSA by remember { mutableStateOf(currentUseECDSA) }
    var selectedRSAKeySize by remember { mutableStateOf(currentRSAKeySize) }
    var selectedECDSACurve by remember { mutableStateOf(currentECDSACurve) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Select Authentication Algorithm") },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    "Choose the algorithm for authentication:",
                    style = MaterialTheme.typography.bodyMedium
                )

                Divider()

                // ========== ECDSA Section ==========
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RadioButton(
                        selected = selectedUseECDSA,
                        onClick = { selectedUseECDSA = true }
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        "ECDSA (Elliptic Curve)",
                        style = MaterialTheme.typography.bodyLarge
                    )
                }

                if (selectedUseECDSA) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(start = 40.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        Text(
                            "Select Curve:",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        // P-256 (Recommended)
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(
                                selected = selectedECDSACurve == ECDSAAuthProvider.CurveType.P256,
                                onClick = { selectedECDSACurve = ECDSAAuthProvider.CurveType.P256 }
                            )
                            Column {
                                Text("P-256 (Recommended)", style = MaterialTheme.typography.bodyMedium)
                                Text(
                                    "256-bit, ~128-bit security, fast",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Color.Gray
                                )
                            }
                        }

                        // P-224
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(
                                selected = selectedECDSACurve == ECDSAAuthProvider.CurveType.P224,
                                onClick = { selectedECDSACurve = ECDSAAuthProvider.CurveType.P224 }
                            )
                            Column {
                                Text("P-224", style = MaterialTheme.typography.bodyMedium)
                                Text(
                                    "224-bit, ~112-bit security",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Color.Gray
                                )
                            }
                        }

                        // P-384
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(
                                selected = selectedECDSACurve == ECDSAAuthProvider.CurveType.P384,
                                onClick = { selectedECDSACurve = ECDSAAuthProvider.CurveType.P384 }
                            )
                            Column {
                                Text("P-384 (High Security)", style = MaterialTheme.typography.bodyMedium)
                                Text(
                                    "384-bit, ~192-bit security, slower",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Color.Gray
                                )
                            }
                        }

                        // P-521
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(
                                selected = selectedECDSACurve == ECDSAAuthProvider.CurveType.P521,
                                onClick = { selectedECDSACurve = ECDSAAuthProvider.CurveType.P521 }
                            )
                            Column {
                                Text("P-521 (Maximum Security)", style = MaterialTheme.typography.bodyMedium)
                                Text(
                                    "521-bit, ~256-bit security, slowest",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Color.Gray
                                )
                            }
                        }
                    }
                }

                Divider()

                // ========== RSA Section ==========
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RadioButton(
                        selected = !selectedUseECDSA,
                        onClick = { selectedUseECDSA = false }
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        "RSA (Traditional)",
                        style = MaterialTheme.typography.bodyLarge
                    )
                }

                if (!selectedUseECDSA) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(start = 40.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        Text(
                            "Select Key Size:",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        // RSA-1024 (Fast, not recommended)
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(
                                selected = selectedRSAKeySize == 1024,
                                onClick = { selectedRSAKeySize = 1024 }
                            )
                            Column {
                                Text("1024-bit (Not Recommended)", style = MaterialTheme.typography.bodyMedium)
                                Text(
                                    "~80-bit security, fast but weak",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Color.Gray
                                )
                            }
                        }

                        // RSA-2048 (Standard)
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(
                                selected = selectedRSAKeySize == 2048,
                                onClick = { selectedRSAKeySize = 2048 }
                            )
                            Column {
                                Text("2048-bit (Standard)", style = MaterialTheme.typography.bodyMedium)
                                Text(
                                    "~112-bit security, good balance",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Color.Gray
                                )
                            }
                        }

                        // RSA-3072
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(
                                selected = selectedRSAKeySize == 3072,
                                onClick = { selectedRSAKeySize = 3072 }
                            )
                            Column {
                                Text("3072-bit (High Security)", style = MaterialTheme.typography.bodyMedium)
                                Text(
                                    "~128-bit security, slower",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Color.Gray
                                )
                            }
                        }

                        // RSA-4096
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(
                                selected = selectedRSAKeySize == 4096,
                                onClick = { selectedRSAKeySize = 4096 }
                            )
                            Column {
                                Text("4096-bit (Maximum Security)", style = MaterialTheme.typography.bodyMedium)
                                Text(
                                    "~152-bit security, very slow",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Color.Gray
                                )
                            }
                        }
                    }
                }

                // Warning if settings changed
                if (selectedUseECDSA != currentUseECDSA ||
                    selectedRSAKeySize != currentRSAKeySize ||
                    selectedECDSACurve != currentECDSACurve) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Surface(
                        color = MaterialTheme.colorScheme.errorContainer,
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text(
                            "⚠️ Changing settings will clear all handshakes",
                            modifier = Modifier.padding(8.dp),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = {
                onConfirm(selectedUseECDSA, selectedRSAKeySize, selectedECDSACurve)
            }) {
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