package com.example.securesms.crypto.utils

import AuthKeyPair
import AuthPrivateKey
import AuthPublicKey
import android.os.Build
import androidx.annotation.RequiresApi
import com.example.securesms.crypto.asymmetric.ECDSAAuthProvider
import com.example.securesms.crypto.asymmetric.RSAAuthProvider
import com.example.securesms.crypto.symmetric.AES
import java.text.DecimalFormat
import kotlin.system.measureTimeMillis

/**
 * Comprehensive Performance Benchmark for Cryptographic Algorithms
 *
 * Tests and compares:
 * - ECDSA: P-192, P-224, P-256, P-384, P-521
 * - RSA: 1024, 2048, 3072, 4096 bits
 *
 * Measures:
 * - Key generation time
 * - Signing time
 * - Verification time
 * - Signature size
 * - Public key size
 */
@RequiresApi(Build.VERSION_CODES.TIRAMISU)
object CryptoPerformanceBenchmark {

    private val df = DecimalFormat("#,##0.00")
    private val dfInt = DecimalFormat("#,##0")

    data class BenchmarkResult(
        val algorithm: String,
        val keySize: Int,
        val keyGenTimeMs: Long,
        val signTimeMs: Long,
        val verifyTimeMs: Long,
        val signatureSize: Int,
        val publicKeySize: Int,
        val securityBits: Int
    ) {
        override fun toString(): String {
            return """
                ┌─────────────────────────────────────────────────────────────
                │ Algorithm: $algorithm
                ├─────────────────────────────────────────────────────────────
                │ Key Size:           ${keySize} bits
                │ Security Level:     ~${securityBits} bits
                │ 
                │ ⏱️  PERFORMANCE:
                │   Key Generation:   ${df.format(keyGenTimeMs)} ms
                │   Sign:             ${df.format(signTimeMs)} ms
                │   Verify:           ${df.format(verifyTimeMs)} ms
                │   Total (Sign+Ver): ${df.format(signTimeMs + verifyTimeMs)} ms
                │ 
                │ 📦 SIZE:
                │   Signature:        ${dfInt.format(signatureSize)} bytes
                │   Public Key:       ${dfInt.format(publicKeySize)} bytes
                │   Total Overhead:   ${dfInt.format(signatureSize + publicKeySize)} bytes
                └─────────────────────────────────────────────────────────────
            """.trimIndent()
        }
    }

    /**
     * Run complete benchmark suite
     */
    fun runFullBenchmark(iterations: Int = 10): List<BenchmarkResult> {
        println("\n" + "=".repeat(65))
        println("🔐 CRYPTOGRAPHIC PERFORMANCE BENCHMARK")
        println("=".repeat(65))
        println("Iterations per test: $iterations")
        println("Test data: 1KB message")
        println()

        val results = mutableListOf<BenchmarkResult>()

        // Benchmark ECDSA curves
        println("\n📊 ECDSA BENCHMARKS")
        println("-".repeat(65))

        ECDSAAuthProvider.CurveType.values().forEach { curveType ->
            results.add(benchmarkECDSA(curveType, iterations))
        }

        // Benchmark RSA key sizes
        println("\n📊 RSA BENCHMARKS")
        println("-".repeat(65))

        listOf(1024, 2048, 3072, 4096).forEach { keySize ->
            results.add(benchmarkRSA(keySize, iterations))
        }

        // Print comparison table
        printComparisonTable(results)

        // Print recommendations
        printRecommendations(results)

        return results
    }

    /**
     * Benchmark ECDSA with specific curve
     */
    private fun benchmarkECDSA(curveType: ECDSAAuthProvider.CurveType, iterations: Int): BenchmarkResult {
        val provider = ECDSAAuthProvider(curveType)
        val testData = ByteArray(1024) { it.toByte() } // 1KB test data

        println("Testing ${provider.algorithm}...")

        // Measure key generation (single run, it's expensive)
        var keyPair: AuthKeyPair? = null
        val keyGenTime = measureTimeMillis {
            keyPair = provider.generateKeyPair()
        }

        val privateKey = extractPrivateKey(keyPair!!)
        val publicKey = extractPublicKey(keyPair!!)

        // Measure signing (average over iterations)
        var totalSignTime = 0L
        var lastSignature: ByteArray? = null
        repeat(iterations) {
            totalSignTime += measureTimeMillis {
                lastSignature = provider.sign(testData, privateKey)
            }
        }
        val avgSignTime = totalSignTime / iterations

        // Measure verification (average over iterations)
        var totalVerifyTime = 0L
        repeat(iterations) {
            totalVerifyTime += measureTimeMillis {
                provider.verify(testData, lastSignature!!, publicKey)
            }
        }
        val avgVerifyTime = totalVerifyTime / iterations

        val result = BenchmarkResult(
            algorithm = provider.algorithm,
            keySize = curveType.bits,
            keyGenTimeMs = keyGenTime,
            signTimeMs = avgSignTime,
            verifyTimeMs = avgVerifyTime,
            signatureSize = provider.getSignatureSize(),
            publicKeySize = provider.getPublicKeySize(),
            securityBits = curveType.securityBits
        )

        println(result)
        return result
    }

    /**
     * Benchmark RSA with specific key size
     */
    private fun benchmarkRSA(keySize: Int, iterations: Int): BenchmarkResult {
        val provider = RSAAuthProvider(keySize)
        val testData = ByteArray(1024) { it.toByte() } // 1KB test data

        println("Testing ${provider.algorithm}...")

        // Measure key generation (single run, it's very expensive for RSA)
        var keyPair: AuthKeyPair? = null
        val keyGenTime = measureTimeMillis {
            keyPair = provider.generateKeyPair()
        }

        val privateKey = extractPrivateKey(keyPair!!)
        val publicKey = extractPublicKey(keyPair!!)

        // Measure signing (average over iterations)
        var totalSignTime = 0L
        var lastSignature: ByteArray? = null
        repeat(iterations) {
            totalSignTime += measureTimeMillis {
                lastSignature = provider.sign(testData, privateKey)
            }
        }
        val avgSignTime = totalSignTime / iterations

        // Measure verification (average over iterations)
        var totalVerifyTime = 0L
        repeat(iterations) {
            totalVerifyTime += measureTimeMillis {
                provider.verify(testData, lastSignature!!, publicKey)
            }
        }
        val avgVerifyTime = totalVerifyTime / iterations

        val securityBits = when (keySize) {
            1024 -> 80
            2048 -> 112
            3072 -> 128
            4096 -> 152
            else -> 0
        }

        val result = BenchmarkResult(
            algorithm = provider.algorithm,
            keySize = keySize,
            keyGenTimeMs = keyGenTime,
            signTimeMs = avgSignTime,
            verifyTimeMs = avgVerifyTime,
            signatureSize = provider.getSignatureSize(),
            publicKeySize = provider.getPublicKeySize(),
            securityBits = securityBits
        )

        println(result)
        return result
    }

    /**
     * Print comparison table
     */
    private fun printComparisonTable(results: List<BenchmarkResult>) {
        println("\n" + "=".repeat(100))
        println("📊 COMPARISON TABLE")
        println("=".repeat(100))

        println(String.format(
            "%-20s | %8s | %8s | %8s | %8s | %12s | %12s",
            "Algorithm", "KeyGen", "Sign", "Verify", "Total", "Sig Size", "Security"
        ))
        println("-".repeat(100))

        results.forEach { r ->
            println(String.format(
                "%-20s | %6.2f ms | %6.2f ms | %6.2f ms | %6.2f ms | %10d B | ~%d bits",
                r.algorithm,
                r.keyGenTimeMs.toDouble(),
                r.signTimeMs.toDouble(),
                r.verifyTimeMs.toDouble(),
                (r.signTimeMs + r.verifyTimeMs).toDouble(),
                r.signatureSize,
                r.securityBits
            ))
        }

        println("=".repeat(100))
    }

    /**
     * Print recommendations based on results
     */
    private fun printRecommendations(results: List<BenchmarkResult>) {
        println("\n" + "=".repeat(65))
        println("💡 RECOMMENDATIONS")
        println("=".repeat(65))

        // Find fastest overall
        val fastest = results.minByOrNull { it.signTimeMs + it.verifyTimeMs }
        println("\n🏆 FASTEST:")
        println("   ${fastest?.algorithm}")
        println("   Total time: ${df.format((fastest?.signTimeMs ?: 0) + (fastest?.verifyTimeMs ?: 0))} ms")

        // Find smallest signature
        val smallest = results.minByOrNull { it.signatureSize }
        println("\n📦 SMALLEST SIGNATURE:")
        println("   ${smallest?.algorithm}")
        println("   Size: ${smallest?.signatureSize} bytes")

        // Find best balance (128-bit security)
        val balanced = results.filter { it.securityBits >= 128 }
            .minByOrNull { it.signTimeMs + it.verifyTimeMs }
        println("\n⚖️  BEST BALANCE (≥128-bit security):")
        println("   ${balanced?.algorithm}")
        println("   Total time: ${df.format((balanced?.signTimeMs ?: 0) + (balanced?.verifyTimeMs ?: 0))} ms")
        println("   Signature: ${balanced?.signatureSize} bytes")

        // Recommended for production
        val p256 = results.find { it.algorithm == "ECDSA-P256" }
        println("\n✅ RECOMMENDED FOR PRODUCTION:")
        println("   ECDSA-P256")
        println("   Why: Best balance of speed, size, and security (128-bit)")
        println("   Total time: ${df.format((p256?.signTimeMs ?: 0) + (p256?.verifyTimeMs ?: 0))} ms")
        println("   Signature: ${p256?.signatureSize} bytes")

        println("\n" + "=".repeat(65))
    }

    /**
     * Benchmark AES encryption/decryption
     */
    fun benchmarkAES(iterations: Int = 100): String {
        println("\n" + "=".repeat(65))
        println("🔐 AES ENCRYPTION BENCHMARK")
        println("=".repeat(65))

        val aes = AES()
        val testData = ByteArray(1024) { it.toByte() } // 1KB
        val results = StringBuilder()

        results.append("\nTest data: 1KB\n")
        results.append("Iterations: $iterations\n\n")

        listOf(
            AES.KEY_SIZE_128 to "AES-128",
            AES.KEY_SIZE_192 to "AES-192",
            AES.KEY_SIZE_256 to "AES-256"
        ).forEach { (keySize, name) ->
            val key = AES.generateKey(keySize)

            var totalEncryptTime = 0L
            var encrypted: AES.EncryptedMessage? = null
            repeat(iterations) {
                totalEncryptTime += measureTimeMillis {
                    encrypted = aes.encrypt(testData, key)
                }
            }
            val avgEncryptTime = totalEncryptTime / iterations

            var totalDecryptTime = 0L
            repeat(iterations) {
                totalDecryptTime += measureTimeMillis {
                    aes.decrypt(encrypted!!, key)
                }
            }
            val avgDecryptTime = totalDecryptTime / iterations

            results.append("$name:\n")
            results.append("  Encryption: ${df.format(avgEncryptTime)} ms\n")
            results.append("  Decryption: ${df.format(avgDecryptTime)} ms\n")
            results.append("  Total:      ${df.format(avgEncryptTime + avgDecryptTime)} ms\n")
            results.append("  Overhead:   ${encrypted!!.ciphertext.size - testData.size} bytes\n\n")

            println(results.toString().lines().takeLast(5).joinToString("\n"))
        }

        println("=".repeat(65))
        return results.toString()
    }

    /**
     * Compare handshake overhead for different algorithms
     */
    fun compareHandshakeOverhead(): String {
        println("\n" + "=".repeat(65))
        println("📊 HANDSHAKE OVERHEAD COMPARISON")
        println("=".repeat(65))

        val results = StringBuilder()
        results.append("\nEstimated SMS overhead (approximate):\n\n")

        // ECDSA overhead
        val ecdsaCurves = listOf(
            ECDSAAuthProvider.CurveType.P224,
            ECDSAAuthProvider.CurveType.P256,
            ECDSAAuthProvider.CurveType.P384,
            ECDSAAuthProvider.CurveType.P521
        )

        ecdsaCurves.forEach { curve ->
            val provider = ECDSAAuthProvider(curve)
            val totalSize = provider.getSignatureSize() + provider.getPublicKeySize()
            val smsCount = (totalSize + 159) / 160 // SMS segments

            results.append(String.format(
                "ECDSA-%-6s: %4d bytes → ~%d SMS segments\n",
                curve.name,
                totalSize,
                smsCount
            ))

            println(results.toString().lines().last())
        }

        results.append("\n")

        // RSA overhead
        listOf(1024, 2048, 3072, 4096).forEach { keySize ->
            val provider = RSAAuthProvider(keySize)
            val totalSize = provider.getSignatureSize() + provider.getPublicKeySize()
            val smsCount = (totalSize + 159) / 160

            results.append(String.format(
                "RSA-%-6d: %4d bytes → ~%d SMS segments\n",
                keySize,
                totalSize,
                smsCount
            ))

            println(results.toString().lines().last())
        }

        println("\n" + "=".repeat(65))
        return results.toString()
    }

    // Helper functions to extract keys from AuthKeyPair
    private fun extractPrivateKey(keyPair: AuthKeyPair): AuthPrivateKey {
        return when (keyPair) {
            is AuthKeyPair.RSAAuth -> AuthPrivateKey.RSAAuth(keyPair.keyPair.privateKey)
            is AuthKeyPair.ECDSAAuth -> AuthPrivateKey.ECDSAAuth(keyPair.keyPair.privateKey)
        }
    }

    private fun extractPublicKey(keyPair: AuthKeyPair): AuthPublicKey {
        return when (keyPair) {
            is AuthKeyPair.RSAAuth -> AuthPublicKey.RSAAuth(keyPair.keyPair.publicKey)
            is AuthKeyPair.ECDSAAuth -> AuthPublicKey.ECDSAAuth(keyPair.keyPair.publicKey)
        }
    }
}

/**
 * Run all benchmarks
 */
@RequiresApi(Build.VERSION_CODES.TIRAMISU)
fun main() {
    // Run full cryptographic benchmark
    val results = CryptoPerformanceBenchmark.runFullBenchmark(iterations = 10)

    // Benchmark AES
    CryptoPerformanceBenchmark.benchmarkAES(iterations = 100)

    // Compare handshake overhead
    CryptoPerformanceBenchmark.compareHandshakeOverhead()

    println("\n✅ Benchmark complete!")
}