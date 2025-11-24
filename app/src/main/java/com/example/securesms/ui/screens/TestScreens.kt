package com.example.securesms.ui.screens

import android.os.Build
import androidx.annotation.RequiresApi
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.example.securesms.crypto.asymmetric.ECC
import com.example.securesms.crypto.asymmetric.RSA
import com.example.securesms.crypto.hash.SHA256
import com.example.securesms.crypto.symmetric.AES
import com.example.securesms.crypto.asymmetric.ECCEncryptedMessage
import com.example.securesms.crypto.models.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.math.BigInteger
import javax.crypto.SecretKey

/**
 * Unified Tests Screen with tabs for all cryptographic algorithms:
 * - RSA (Asymmetric)
 * - ECC (Asymmetric)
 * - SHA-256 (Hash)
 * - AES (Symmetric)
 */
@RequiresApi(Build.VERSION_CODES.TIRAMISU)
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TestsScreen() {
    var selectedTab by remember { mutableIntStateOf(0) }

    val tabs = listOf(
        TestTab("RSA", Icons.Default.Lock),
        TestTab("ECC", Icons.Default.Lock),
        TestTab("SHA-256", Icons.Default.Lock),
        TestTab("AES", Icons.Default.Lock)
    )

    Column(modifier = Modifier.fillMaxSize()) {
        // Tab Row
        TabRow(selectedTabIndex = selectedTab) {
            tabs.forEachIndexed { index, tab ->
                Tab(
                    selected = selectedTab == index,
                    onClick = { selectedTab = index },
                    text = { Text(tab.label) },
                    icon = { Icon(tab.icon, contentDescription = tab.label) }
                )
            }
        }

        // Tab Content
        when (selectedTab) {
            0 -> RSATestContent()
            1 -> ECCTestContent()
            2 -> SHA256TestContent()
            3 -> AESTestContent()
        }
    }
}

/**
 * Data class for test tabs
 */
private data class TestTab(
    val label: String,
    val icon: ImageVector
)

// ============================================================================
// RSA TEST CONTENT
// ============================================================================

@Composable
private fun RSATestContent() {
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
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Info Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer
            )
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "RSA (Rivest-Shamir-Adleman)",
                    style = MaterialTheme.typography.titleMedium
                )
                Text(
                    text = """
                        Asymmetric encryption algorithm:
                        • Different keys for encryption/decryption
                        • Public key: encrypt, verify signatures
                        • Private key: decrypt, create signatures
                        • Based on factoring large numbers
                    """.trimIndent(),
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        // Key Generation
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("1. Generate RSA Key Pair", style = MaterialTheme.typography.titleMedium)

                Button(
                    onClick = {
                        scope.launch {
                            isGenerating = true
                            statusMessage = "Generating keys..."
                            try {
                                val (pub, priv) = withContext(Dispatchers.Default) {
                                    RSA.generateKeyPair(1024)
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
                    if (isGenerating) CircularProgressIndicator(modifier = Modifier.size(24.dp))
                    Text(if (isGenerating) "Generating..." else "Generate Key Pair (1024-bit)")
                }

                if (publicKey != null) {
                    Divider()
                    Text("Public Key:", style = MaterialTheme.typography.labelMedium)
                    Text("e = ${publicKey!!.e}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                    Text("n = ${publicKey!!.n.toString(16).take(40)}...", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                }
            }
        }

        // Encryption
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("2. Encrypt Message", style = MaterialTheme.typography.titleMedium)

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
                                ciphertext = encrypted.toString()
                                statusMessage = "✓ Message encrypted"
                            } catch (e: Exception) {
                                statusMessage = "✗ Encryption failed: ${e.message}"
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = publicKey != null && plaintext.isNotEmpty()
                ) {
                    Text("Encrypt")
                }

                if (ciphertext.isNotEmpty()) {
                    Divider()
                    Text("Ciphertext:", style = MaterialTheme.typography.labelMedium)
                    Text(ciphertext.take(100) + "...", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                }
            }
        }

        // Status
        if (statusMessage.isNotEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)
            ) {
                Text(statusMessage, modifier = Modifier.padding(16.dp), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

// ============================================================================
// ECC TEST CONTENT
// ============================================================================

@RequiresApi(Build.VERSION_CODES.TIRAMISU)
@Composable
private fun ECCTestContent() {
    var message by remember { mutableStateOf("Hello ECC!") }
    var useTestCurve by remember { mutableStateOf(true) }
    var aliceKeyPair by remember { mutableStateOf<ECCKeyPair?>(null) }
    var bobKeyPair by remember { mutableStateOf<ECCKeyPair?>(null) }
    var encryptedMessage by remember { mutableStateOf<ECCEncryptedMessage?>(null) }
    var decryptedMessage by remember { mutableStateOf<String?>(null) }
    var aliceSharedSecret by remember { mutableStateOf<ECCPoint?>(null) }
    var bobSharedSecret by remember { mutableStateOf<ECCPoint?>(null) }
    var statusMessage by remember { mutableStateOf("") }

    val ecc = remember { ECC() }
    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(scrollState),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Info Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("ECC (Elliptic Curve Cryptography)", style = MaterialTheme.typography.titleMedium)
                Text(
                    """
                        Based on elliptic curves: y² = x³ + ax + b
                        • Smaller keys than RSA for same security
                        • Efficient for resource-constrained devices
                        • Used in ECDH key exchange
                    """.trimIndent(),
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        // Curve Selection
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Select Curve", style = MaterialTheme.typography.titleMedium)

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = useTestCurve,
                        onClick = { useTestCurve = true },
                        label = { Text("Test Curve (mod 17)") }
                    )
                    FilterChip(
                        selected = !useTestCurve,
                        onClick = { useTestCurve = false },
                        label = { Text("Standard Curve") }
                    )
                }
            }
        }

        // Generate Keys
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Step 1: Generate Key Pairs", style = MaterialTheme.typography.titleMedium)

                Button(
                    onClick = {
                        val curve = if (useTestCurve) ECC.getTestCurve() else ECC.getSecureCurve()
                        aliceKeyPair = ECC.generateKeyPair(curve)
                        bobKeyPair = ECC.generateKeyPair(curve)
                        statusMessage = "✓ Key pairs generated for Alice and Bob"
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Generate Alice & Bob Key Pairs")
                }

                if (aliceKeyPair != null && bobKeyPair != null) {
                    Divider()
                    Text("Alice Public: Q = ${aliceKeyPair!!.publicKey.Q.toCompactString()}",
                        style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                    Text("Bob Public: Q = ${bobKeyPair!!.publicKey.Q.toCompactString()}",
                        style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                }
            }
        }

        // ECDH Key Exchange
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Step 2: ECDH Key Exchange", style = MaterialTheme.typography.titleMedium)

                Button(
                    onClick = {
                        if (aliceKeyPair != null && bobKeyPair != null) {
                            aliceSharedSecret = ecc.generateSharedSecret(aliceKeyPair!!.privateKey, bobKeyPair!!.publicKey)
                            bobSharedSecret = ecc.generateSharedSecret(bobKeyPair!!.privateKey, aliceKeyPair!!.publicKey)
                            val match = aliceSharedSecret == bobSharedSecret
                            statusMessage = if (match) "✓ Shared secrets match!" else "✗ Shared secrets don't match"
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = aliceKeyPair != null && bobKeyPair != null
                ) {
                    Text("Compute Shared Secret")
                }

                if (aliceSharedSecret != null && bobSharedSecret != null) {
                    Divider()
                    Text("Alice's S = ${aliceSharedSecret!!.toCompactString()}",
                        style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                    Text("Bob's S = ${bobSharedSecret!!.toCompactString()}",
                        style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                }
            }
        }

        // Status
        if (statusMessage.isNotEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)
            ) {
                Text(statusMessage, modifier = Modifier.padding(16.dp), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

// ============================================================================
// SHA-256 TEST CONTENT
// ============================================================================

@Composable
private fun SHA256TestContent() {
    var inputText by remember { mutableStateOf("Hello, SHA-256!") }
    var hashResult by remember { mutableStateOf("") }
    var statusMessage by remember { mutableStateOf("") }

    val sha256 = remember { SHA256() }
    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(scrollState),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Info Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("SHA-256 Hash Function", style = MaterialTheme.typography.titleMedium)
                Text(
                    """
                        Cryptographic hash function:
                        • Fixed 256-bit (32-byte) output
                        • One-way: cannot reverse
                        • Collision-resistant
                        • Avalanche effect: small changes → large differences
                    """.trimIndent(),
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        // Hash Generation
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Hash Generation", style = MaterialTheme.typography.titleMedium)

                OutlinedTextField(
                    value = inputText,
                    onValueChange = { inputText = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Input Text") },
                    minLines = 3
                )

                Button(
                    onClick = {
                        if (inputText.isNotEmpty()) {
                            hashResult = sha256.hashToHex(inputText)
                            statusMessage = "✓ Hash computed successfully"
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Compute Hash")
                }

                if (hashResult.isNotEmpty()) {
                    Divider()
                    Text("SHA-256 Hash:", style = MaterialTheme.typography.labelMedium)
                    Text(hashResult, style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.secondary)
                    Text("Length: ${hashResult.length} hex characters (${hashResult.length / 2} bytes)",
                        style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        // Avalanche Effect
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Avalanche Effect Demo", style = MaterialTheme.typography.titleMedium)

                Button(
                    onClick = {
                        val text1 = "Hello World"
                        val text2 = "Hello World!"
                        val hash1 = sha256.hashToHex(text1)
                        val hash2 = sha256.hashToHex(text2)

                        statusMessage = """
                            Text 1: "$text1"
                            Hash 1: ${hash1.take(32)}...
                            
                            Text 2: "$text2" (added '!')
                            Hash 2: ${hash2.take(32)}...
                            
                            Despite only 1 character change, hashes are completely different!
                        """.trimIndent()
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Show Avalanche Effect")
                }
            }
        }

        // Status
        if (statusMessage.isNotEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)
            ) {
                Text(statusMessage, modifier = Modifier.padding(16.dp), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

// ============================================================================
// AES TEST CONTENT
// ============================================================================

@RequiresApi(Build.VERSION_CODES.TIRAMISU)
@Composable
private fun AESTestContent() {
    var message by remember { mutableStateOf("Secret message for AES!") }
    var keySize by remember { mutableStateOf(AES.KEY_SIZE_256) }
    var secretKey by remember { mutableStateOf<SecretKey?>(null) }
    var encryptedMessage by remember { mutableStateOf<AES.EncryptedMessage?>(null) }
    var decryptedMessage by remember { mutableStateOf<String?>(null) }
    var statusMessage by remember { mutableStateOf("") }

    val aes = remember { AES() }
    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(scrollState),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Info Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("AES (Advanced Encryption Standard)", style = MaterialTheme.typography.titleMedium)
                Text(
                    """
                        Symmetric block cipher:
                        • Same key for encryption/decryption
                        • Block size: 128 bits
                        • Key sizes: 128, 192, or 256 bits
                        • Mode: GCM (provides encryption + authentication)
                    """.trimIndent(),
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        // Key Generation
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Step 1: Generate AES Key", style = MaterialTheme.typography.titleMedium)

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = keySize == AES.KEY_SIZE_128,
                        onClick = { keySize = AES.KEY_SIZE_128 },
                        label = { Text("128-bit") }
                    )
                    FilterChip(
                        selected = keySize == AES.KEY_SIZE_192,
                        onClick = { keySize = AES.KEY_SIZE_192 },
                        label = { Text("192-bit") }
                    )
                    FilterChip(
                        selected = keySize == AES.KEY_SIZE_256,
                        onClick = { keySize = AES.KEY_SIZE_256 },
                        label = { Text("256-bit") }
                    )
                }

                Button(
                    onClick = {
                        secretKey = AES.generateKey(keySize)
                        statusMessage = "✓ Generated $keySize-bit AES key"
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Generate Key")
                }

                if (secretKey != null) {
                    Divider()
                    val keyBytes = secretKey!!.encoded
                    val keyHex = keyBytes.joinToString("") { "%02x".format(it) }
                    Text("Key: ${keyHex.take(32)}...", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                    Text("Size: ${keyBytes.size} bytes (${keyBytes.size * 8} bits)", style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        // Encryption
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Step 2: Encrypt Message", style = MaterialTheme.typography.titleMedium)

                OutlinedTextField(
                    value = message,
                    onValueChange = { message = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Message") },
                    minLines = 2
                )

                Button(
                    onClick = {
                        if (secretKey != null && message.isNotEmpty()) {
                            encryptedMessage = aes.encrypt(message, secretKey!!)
                            statusMessage = "✓ Message encrypted with AES-GCM"
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = secretKey != null
                ) {
                    Text("Encrypt")
                }

                if (encryptedMessage != null) {
                    Divider()
                    val encrypted = encryptedMessage!!
                    val ciphertextHex = encrypted.ciphertext.joinToString("") { "%02x".format(it) }
                    Text("Ciphertext: ${ciphertextHex.take(40)}...", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                    Text("Size: ${encrypted.ciphertext.size} bytes", style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        // Decryption
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Step 3: Decrypt Message", style = MaterialTheme.typography.titleMedium)

                Button(
                    onClick = {
                        if (secretKey != null && encryptedMessage != null) {
                            try {
                                decryptedMessage = aes.decryptToString(encryptedMessage!!, secretKey!!)
                                val match = decryptedMessage == message
                                statusMessage = if (match) "✓ Decrypted successfully! Message matches original."
                                else "✗ Decrypted but doesn't match original"
                            } catch (e: Exception) {
                                statusMessage = "✗ Decryption failed: ${e.message}"
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = secretKey != null && encryptedMessage != null
                ) {
                    Text("Decrypt")
                }

                if (decryptedMessage != null) {
                    Divider()
                    Text("Decrypted: $decryptedMessage", style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
                }
            }
        }

        // Status
        if (statusMessage.isNotEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)
            ) {
                Text(statusMessage, modifier = Modifier.padding(16.dp), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}