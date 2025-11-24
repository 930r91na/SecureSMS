package com.example.securesms.ui.screens

import android.os.Build
import androidx.annotation.RequiresApi
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.example.securesms.crypto.asymmetric.ECC
import com.example.securesms.crypto.asymmetric.ECCEncryptedMessage
import com.example.securesms.crypto.models.*
import java.math.BigInteger

@RequiresApi(Build.VERSION_CODES.TIRAMISU)
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ECCTestScreen(onBackClick: () -> Unit) {
    var message by remember { mutableStateOf("Hello ECC!") }
    var useTestCurve by remember { mutableStateOf(true) }

    // Key pair state
    var aliceKeyPair by remember { mutableStateOf<ECCKeyPair?>(null) }
    var bobKeyPair by remember { mutableStateOf<ECCKeyPair?>(null) }

    // Encryption state
    var encryptedMessage by remember { mutableStateOf<ECCEncryptedMessage?>(null) }
    var decryptedMessage by remember { mutableStateOf<String?>(null) }

    // ECDH shared secret state
    var aliceSharedSecret by remember { mutableStateOf<ECCPoint?>(null) }
    var bobSharedSecret by remember { mutableStateOf<ECCPoint?>(null) }

    // Status messages
    var statusMessage by remember { mutableStateOf("") }
    var isProcessing by remember { mutableStateOf(false) }

    val ecc = remember { ECC() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("ECC Test") },
                navigationIcon = {
                    IconButton(onClick = onBackClick) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Info Card
            InfoCard()

            // Curve Selection
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Curve Selection",
                        style = MaterialTheme.typography.titleMedium
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        FilterChip(
                            selected = useTestCurve,
                            onClick = { useTestCurve = true },
                            label = { Text("Test Curve (mod 17)") }
                        )
                        FilterChip(
                            selected = !useTestCurve,
                            onClick = { useTestCurve = false },
                            label = { Text("Secure Curve (256-bit)") }
                        )
                    }
                }
            }

            // Step 1: Key Generation
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Step 1: Generate Key Pairs",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary
                    )

                    Button(
                        onClick = {
                            isProcessing = true
                            statusMessage = "Generating key pairs..."

                            val curve = if (useTestCurve) {
                                ECC.getTestCurve()
                            } else {
                                ECC.getSecureCurve()
                            }

                            aliceKeyPair = ECC.generateKeyPair(curve)
                            bobKeyPair = ECC.generateKeyPair(curve)

                            statusMessage = "✓ Key pairs generated for Alice and Bob"
                            isProcessing = false
                        },
                        enabled = !isProcessing,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Generate Keys")
                    }

                    if (aliceKeyPair != null) {
                        Divider()
                        Text(
                            text = "Alice's Keys:",
                            style = MaterialTheme.typography.titleSmall
                        )
                        Text(
                            text = "Private: d = ${aliceKeyPair!!.privateKey.d}",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace
                        )
                        Text(
                            text = "Public: Q = ${aliceKeyPair!!.publicKey.Q}",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace
                        )
                    }

                    if (bobKeyPair != null) {
                        Divider()
                        Text(
                            text = "Bob's Keys:",
                            style = MaterialTheme.typography.titleSmall
                        )
                        Text(
                            text = "Private: d = ${bobKeyPair!!.privateKey.d}",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace
                        )
                        Text(
                            text = "Public: Q = ${bobKeyPair!!.publicKey.Q}",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }

            // Step 2: ECDH Key Exchange
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Step 2: ECDH Key Exchange",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary
                    )

                    Text(
                        text = "Compute shared secret: S = a·B = b·A",
                        style = MaterialTheme.typography.bodySmall
                    )

                    Button(
                        onClick = {
                            if (aliceKeyPair != null && bobKeyPair != null) {
                                isProcessing = true
                                statusMessage = "Computing shared secrets..."

                                // Alice computes S = a·B
                                aliceSharedSecret = ecc.generateSharedSecret(
                                    aliceKeyPair!!.privateKey,
                                    bobKeyPair!!.publicKey
                                )

                                // Bob computes S = b·A
                                bobSharedSecret = ecc.generateSharedSecret(
                                    bobKeyPair!!.privateKey,
                                    aliceKeyPair!!.publicKey
                                )

                                val match = aliceSharedSecret == bobSharedSecret
                                statusMessage = if (match) {
                                    "✓ Shared secrets match! ECDH successful"
                                } else {
                                    "✗ Shared secrets don't match"
                                }

                                isProcessing = false
                            } else {
                                statusMessage = "⚠ Generate keys first"
                            }
                        },
                        enabled = !isProcessing && aliceKeyPair != null && bobKeyPair != null,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Compute Shared Secret")
                    }

                    if (aliceSharedSecret != null) {
                        Divider()
                        Text(
                            text = "Alice's shared secret:",
                            style = MaterialTheme.typography.titleSmall
                        )
                        Text(
                            text = "S = $aliceSharedSecret",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace
                        )
                    }

                    if (bobSharedSecret != null) {
                        Divider()
                        Text(
                            text = "Bob's shared secret:",
                            style = MaterialTheme.typography.titleSmall
                        )
                        Text(
                            text = "S = $bobSharedSecret",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace
                        )

                        if (aliceSharedSecret == bobSharedSecret) {
                            Text(
                                text = "✓ Secrets match!",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                    }
                }
            }

            // Step 3: Encryption
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Step 3: Encrypt Message",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary
                    )

                    OutlinedTextField(
                        value = message,
                        onValueChange = { message = it },
                        label = { Text("Message to encrypt") },
                        modifier = Modifier.fillMaxWidth()
                    )

                    Button(
                        onClick = {
                            if (bobKeyPair != null) {
                                isProcessing = true
                                statusMessage = "Encrypting message..."

                                // Alice encrypts message for Bob using Bob's public key
                                encryptedMessage = ecc.encrypt(message, bobKeyPair!!.publicKey)

                                statusMessage = "✓ Message encrypted"
                                isProcessing = false
                            } else {
                                statusMessage = "⚠ Generate keys first"
                            }
                        },
                        enabled = !isProcessing && bobKeyPair != null && message.isNotEmpty(),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Encrypt (Alice → Bob)")
                    }

                    if (encryptedMessage != null) {
                        Divider()
                        Text(
                            text = "Encrypted Message:",
                            style = MaterialTheme.typography.titleSmall
                        )
                        Text(
                            text = "R = ${encryptedMessage!!.R.toCompactString()}",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace
                        )
                        Text(
                            text = "Ciphertext: ${encryptedMessage!!.ciphertext.size} bytes",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }

            // Step 4: Decryption
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Step 4: Decrypt Message",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary
                    )

                    Button(
                        onClick = {
                            if (encryptedMessage != null && bobKeyPair != null) {
                                isProcessing = true
                                statusMessage = "Decrypting message..."

                                // Bob decrypts using his private key
                                decryptedMessage = ecc.decrypt(
                                    encryptedMessage!!,
                                    bobKeyPair!!.privateKey
                                )

                                val match = decryptedMessage == message
                                statusMessage = if (match) {
                                    "✓ Decryption successful! Message matches"
                                } else {
                                    "⚠ Decrypted message doesn't match original"
                                }

                                isProcessing = false
                            } else {
                                statusMessage = "⚠ Encrypt a message first"
                            }
                        },
                        enabled = !isProcessing && encryptedMessage != null,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Decrypt (Bob)")
                    }

                    if (decryptedMessage != null) {
                        Divider()
                        Text(
                            text = "Decrypted Message:",
                            style = MaterialTheme.typography.titleSmall
                        )
                        Text(
                            text = decryptedMessage!!,
                            style = MaterialTheme.typography.bodyMedium,
                            color = if (decryptedMessage == message) {
                                MaterialTheme.colorScheme.primary
                            } else {
                                MaterialTheme.colorScheme.error
                            }
                        )

                        Text(
                            text = "Original: $message",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }

            // Status Card
            if (statusMessage.isNotEmpty()) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer
                    )
                ) {
                    Text(
                        text = statusMessage,
                        modifier = Modifier.padding(16.dp),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }
        }
    }
}

@Composable
private fun InfoCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.tertiaryContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text(
                text = "ℹ️ How ECC Works:",
                style = MaterialTheme.typography.titleSmall
            )
            Text(
                text = "• Curve: y² = x³ + ax + b (mod p)",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace
            )
            Text(
                text = "• Private key: random d ∈ [1, n-1]",
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                text = "• Public key: Q = d·G (scalar multiplication)",
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                text = "• ECDH: Shared secret S = a·B = b·A",
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                text = "• Point Addition: P + Q uses curve geometry",
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}