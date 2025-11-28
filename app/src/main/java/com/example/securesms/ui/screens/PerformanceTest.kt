package com.example.securesms.ui.screens

import android.os.Build
import androidx.annotation.RequiresApi
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.securesms.crypto.utils.CryptoPerformanceBenchmark
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@RequiresApi(Build.VERSION_CODES.TIRAMISU)
@Composable
fun PerformanceTestScreen() {
    val scope = rememberCoroutineScope()
    val scrollState = rememberScrollState()

    var isRunning by remember { mutableStateOf(false) }
    var testResults by remember { mutableStateOf("") }
    var progress by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
    ) {
        // Header
        Surface(
            shadowElevation = 4.dp,
            color = MaterialTheme.colorScheme.primaryContainer
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    "🔐 Performance Benchmarks",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    "Compare speeds and sizes of crypto algorithms",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                )
            }
        }

        // Control buttons
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    "Select Benchmark:",
                    style = MaterialTheme.typography.titleMedium
                )

                // Run Full Benchmark
                Button(
                    onClick = {
                        scope.launch {
                            isRunning = true
                            testResults = ""
                            progress = "🔄 Running full benchmark suite...\n\n"

                            testResults = withContext(Dispatchers.Default) {
                                val stringBuilder = StringBuilder()

                                // Redirect println to capture output
                                val originalOut = System.out
                                val collector = object : java.io.OutputStream() {
                                    override fun write(b: Int) {
                                        stringBuilder.append(b.toChar())
                                    }
                                }

                                System.setOut(java.io.PrintStream(collector))

                                try {
                                    CryptoPerformanceBenchmark.runFullBenchmark(iterations = 5)
                                    testResults = stringBuilder.toString()
                                } finally {
                                    System.setOut(originalOut)
                                }

                                stringBuilder.toString()
                            }

                            progress = "✅ Benchmark complete!"
                            isRunning = false
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isRunning
                ) {
                    Icon(Icons.Default.PlayArrow, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Run Full Benchmark (All Algorithms)")
                }

                // Quick ECDSA vs RSA
                Button(
                    onClick = {
                        scope.launch {
                            isRunning = true
                            testResults = ""
                            progress = "🔄 Comparing ECDSA vs RSA...\n\n"

                            testResults = withContext(Dispatchers.Default) {
                                buildString {
                                    append("═══════════════════════════════════════\n")
                                    append("QUICK COMPARISON: ECDSA-P256 vs RSA-2048\n")
                                    append("═══════════════════════════════════════\n\n")

                                    val ecdsaResult = CryptoPerformanceBenchmark.runFullBenchmark(5)
                                        .find { it.algorithm == "ECDSA-P256" }
                                    val rsaResult = CryptoPerformanceBenchmark.runFullBenchmark(5)
                                        .find { it.algorithm == "RSA-2048" }

                                    if (ecdsaResult != null && rsaResult != null) {
                                        append("ECDSA-P256:\n")
                                        append("  Sign:      ${String.format("%.2f", ecdsaResult.signTimeMs.toDouble())} ms\n")
                                        append("  Verify:    ${String.format("%.2f", ecdsaResult.verifyTimeMs.toDouble())} ms\n")
                                        append("  Signature: ${ecdsaResult.signatureSize} bytes\n\n")

                                        append("RSA-2048:\n")
                                        append("  Sign:      ${String.format("%.2f", rsaResult.signTimeMs.toDouble())} ms\n")
                                        append("  Verify:    ${String.format("%.2f", rsaResult.verifyTimeMs.toDouble())} ms\n")
                                        append("  Signature: ${rsaResult.signatureSize} bytes\n\n")

                                        val speedup = rsaResult.signTimeMs.toDouble() / ecdsaResult.signTimeMs.toDouble()
                                        append("WINNER: ")
                                        if (speedup > 1) {
                                            append("ECDSA is ${String.format("%.1f", speedup)}x faster! ⚡\n")
                                        } else {
                                            append("RSA is ${String.format("%.1f", 1/speedup)}x faster! ⚡\n")
                                        }
                                    }
                                }
                            }

                            progress = "✅ Comparison complete!"
                            isRunning = false
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isRunning
                ) {
                    Icon(Icons.Default.KeyboardArrowDown, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Quick Compare: ECDSA vs RSA")
                }

                // AES Benchmark
                Button(
                    onClick = {
                        scope.launch {
                            isRunning = true
                            testResults = ""
                            progress = "🔄 Benchmarking AES encryption...\n\n"

                            testResults = withContext(Dispatchers.Default) {
                                CryptoPerformanceBenchmark.benchmarkAES(iterations = 50)
                            }

                            progress = "✅ AES benchmark complete!"
                            isRunning = false
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isRunning
                ) {
                    Icon(Icons.Default.Lock, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Benchmark AES Encryption")
                }

                // Handshake Overhead
                Button(
                    onClick = {
                        scope.launch {
                            isRunning = true
                            testResults = ""
                            progress = "🔄 Analyzing handshake overhead...\n\n"

                            testResults = withContext(Dispatchers.Default) {
                                CryptoPerformanceBenchmark.compareHandshakeOverhead()
                            }

                            progress = "✅ Analysis complete!"
                            isRunning = false
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isRunning
                ) {
                    Icon(Icons.Default.Email, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("SMS Overhead Analysis")
                }
            }
        }

        // Progress indicator
        if (isRunning) {
            LinearProgressIndicator(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
            )
        }

        // Progress text
        if (progress.isNotEmpty()) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (progress.contains("✅"))
                        MaterialTheme.colorScheme.primaryContainer
                    else
                        MaterialTheme.colorScheme.secondaryContainer
                )
            ) {
                Text(
                    text = progress,
                    modifier = Modifier.padding(16.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Bold
                )
            }
        }

        // Results display
        if (testResults.isNotEmpty()) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .padding(16.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(scrollState)
                        .padding(16.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "Results:",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )

                        TextButton(
                            onClick = {
                                // Copy to clipboard functionality
                                testResults = ""
                            }
                        ) {
                            Icon(Icons.Default.Clear, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Clear")
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    Surface(
                        color = Color.Black,
                        shape = MaterialTheme.shapes.small
                    ) {
                        Text(
                            text = testResults,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(12.dp),
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            color = Color.Green,
                            lineHeight = 14.sp
                        )
                    }
                }
            }
        } else if (!isRunning) {
            // Empty state
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Icon(
                        Icons.Default.KeyboardArrowUp,
                        contentDescription = null,
                        modifier = Modifier.size(64.dp),
                        tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.5f)
                    )
                    Text(
                        "Select a benchmark to begin",
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onBackground.copy(alpha = 0.6f)
                    )
                }
            }
        }
    }
}