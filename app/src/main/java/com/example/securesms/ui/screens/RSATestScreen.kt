package com.example.securesms.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.example.securesms.crypto.asymmetric.RSA
import com.example.securesms.crypto.models.RSAPublicKey
import com.example.securesms.crypto.models.RSAPrivateKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.math.BigInteger

@Composable
fun RSATestScreen() {
    var publicKey by remember { mutableStateOf<RSAPublicKey?>(null) }
    var privateKey by remember { mutableStateOf<RSAPrivateKey?>(null) }
    var isGenerating by remember { mutableStateOf(false) }

    var plaintext by remember { mutableStateOf("Hello, SecureSMS!") }
    var ciphertext by remember { mutableStateOf("") }
    var decryptedText by remember { mutableStateOf("") }

    var statusMessage by remember { mutableStateOf("") }

    val scope = rememberCoroutineScope()
    val rsa = remember { RSA() }
    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(scrollState),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Title
        Text(
            text = "RSA Encryption Test",
            style = MaterialTheme.typography.headlineMedium
        )

        // Key Generation Section
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
                    text = "1. Generate RSA Key Pair",
                    style = MaterialTheme.typography.titleMedium
                )

                Button(
                    onClick = {
                        scope.launch {
                            isGenerating = true
                            statusMessage = "Generating keys..."
                            try {
                                val (pub, priv) = withContext(Dispatchers.Default) {
                                    RSA.generateKeyPair(1024) // Use 1024 for faster generation
                                }
                                publicKey = pub
                                privateKey = priv
                                statusMessage = "✓ Keys generated successfully!"
                            } catch (e: Exception) {
                                statusMessage = "✗ Error: ${e.message}"
                            } finally {
                                isGenerating = false
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isGenerating
                ) {
                    if (isGenerating) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(24.dp),
                            color = MaterialTheme.colorScheme.onPrimary
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                    }
                    Text(if (isGenerating) "Generating..." else "Generate Key Pair (1024-bit)")
                }

                if (publicKey != null) {
                    Column {
                        Text(
                            text = "Public Key:",
                            style = MaterialTheme.typography.labelMedium
                        )
                        Text(
                            text = "e = ${publicKey!!.e}",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace
                        )
                        Text(
                            text = "n = ${publicKey!!.n.toString(16).take(40)}...",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }
        }

        // Encryption Section
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.secondaryContainer
            )
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = "2. Encrypt Message",
                    style = MaterialTheme.typography.titleMedium
                )

                OutlinedTextField(
                    value = plaintext,
                    onValueChange = { plaintext = it },
                    label = { Text("Plaintext") },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = publicKey != null
                )

                Button(
                    onClick = {
                        scope.launch {
                            try {
                                val encrypted = withContext(Dispatchers.Default) {
                                    rsa.encryptString(plaintext, publicKey!!)
                                }
                                ciphertext = encrypted.joinToString(",") { it.toString(16) }
                                statusMessage = "✓ Message encrypted!"
                                decryptedText = "" // Clear previous decryption
                            } catch (e: Exception) {
                                statusMessage = "✗ Encryption error: ${e.message}"
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = publicKey != null && plaintext.isNotBlank()
                ) {
                    Text("Encrypt with Public Key")
                }

                if (ciphertext.isNotBlank()) {
                    Column {
                        Text(
                            text = "Ciphertext (hex blocks):",
                            style = MaterialTheme.typography.labelMedium
                        )
                        Text(
                            text = ciphertext.take(200) + if (ciphertext.length > 200) "..." else "",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }
        }

        // Decryption Section
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.tertiaryContainer
            )
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = "3. Decrypt Message",
                    style = MaterialTheme.typography.titleMedium
                )

                Button(
                    onClick = {
                        scope.launch {
                            try {
                                val blocks = ciphertext.split(",")
                                    .map { BigInteger(it.trim(), 16) }

                                val decrypted = withContext(Dispatchers.Default) {
                                    rsa.decryptString(blocks, privateKey!!)
                                }
                                decryptedText = decrypted

                                if (decrypted == plaintext) {
                                    statusMessage = "✓ Decryption successful! Message matches original."
                                } else {
                                    statusMessage = "⚠ Decrypted but message doesn't match"
                                }
                            } catch (e: Exception) {
                                statusMessage = "✗ Decryption error: ${e.message}"
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = privateKey != null && ciphertext.isNotBlank()
                ) {
                    Text("Decrypt with Private Key")
                }

                if (decryptedText.isNotBlank()) {
                    Column {
                        Text(
                            text = "Decrypted Text:",
                            style = MaterialTheme.typography.labelMedium
                        )
                        Text(
                            text = decryptedText,
                            style = MaterialTheme.typography.bodyMedium,
                            color = if (decryptedText == plaintext)
                                MaterialTheme.colorScheme.primary
                            else
                                MaterialTheme.colorScheme.error
                        )
                    }
                }
            }
        }

        // Status Messages
        if (statusMessage.isNotBlank()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = when {
                        statusMessage.startsWith("✓") -> MaterialTheme.colorScheme.primaryContainer
                        statusMessage.startsWith("✗") -> MaterialTheme.colorScheme.errorContainer
                        else -> MaterialTheme.colorScheme.surfaceVariant
                    }
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