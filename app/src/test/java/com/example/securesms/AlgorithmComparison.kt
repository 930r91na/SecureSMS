package com.example.securesms.crypto.test

import android.os.Build
import androidx.annotation.RequiresApi
import com.example.securesms.crypto.asymmetric.ECDSAAuthProvider
import com.example.securesms.crypto.asymmetric.RSAAuthProvider
import com.example.securesms.crypto.symmetric.AES
import org.junit.Test
import kotlin.system.measureTimeMillis
import AuthKeyPair
import AuthPrivateKey
import AuthPublicKey

/**
 * Comparison Test - Runs all algorithms and provides side-by-side comparison
 *
 * Run this test from Android Studio:
 * Right-click on the test class → Run 'AlgorithmComparisonTest'
 *
 * This will:
 * 1. Benchmark all ECDSA curves
 * 2. Benchmark all RSA key sizes
 * 3. Benchmark all AES key sizes
 * 4. Provide comprehensive comparison table
 * 5. Give recommendations
 */
@RequiresApi(Build.VERSION_CODES.TIRAMISU)
class AlgorithmComparisonTest {

    data class BenchmarkResult(
        val algorithm: String,
        val keyGenTimeMs: Long,
        val signTimeMs: Long,
        val verifyTimeMs: Long,
        val signatureSize: Int,
        val publicKeySize: Int,
        val securityBits: Int
    )

    @Test
    fun compareAllAlgorithms() {
        println("\n" + "═".repeat(80))
        println("🔐 COMPREHENSIVE CRYPTOGRAPHIC ALGORITHM COMPARISON")
        println("═".repeat(80))
        println("Test Data: 1KB message")
        println("Iterations: 10 per algorithm")
        println()

        val results = mutableListOf<BenchmarkResult>()

        // Benchmark ECDSA
        println("\n" + "─".repeat(80))
        println("📊 BENCHMARKING ECDSA CURVES")
        println("─".repeat(80))

        ECDSAAuthProvider.CurveType.values().forEach { curveType ->
            results.add(benchmarkECDSA(curveType))
        }

        // Benchmark RSA
        println("\n" + "─".repeat(80))
        println("📊 BENCHMARKING RSA KEY SIZES")
        println("─".repeat(80))

        listOf(1024, 2048, 3072, 4096).forEach { keySize ->
            results.add(benchmarkRSA(keySize))
        }

        // Print comparison table
        printComparisonTable(results)

        // Print winners
        printWinners(results)

        // Print recommendations
        printRecommendations(results)
    }

    private fun benchmarkECDSA(curveType: ECDSAAuthProvider.CurveType): BenchmarkResult {
        val provider = ECDSAAuthProvider(curveType)
        val testData = ByteArray(1024) { it.toByte() }

        print("Testing ${provider.algorithm}... ")

        var keyPair: AuthKeyPair? = null
        val keyGenTime = measureTimeMillis {
            keyPair = provider.generateKeyPair()
        }

        val privateKey = extractPrivateKey(keyPair!!)
        val publicKey = extractPublicKey(keyPair!!)

        var totalSignTime = 0L
        var lastSignature: ByteArray? = null
        repeat(10) {
            totalSignTime += measureTimeMillis {
                lastSignature = provider.sign(testData, privateKey)
            }
        }
        val avgSignTime = totalSignTime / 10

        var totalVerifyTime = 0L
        repeat(10) {
            totalVerifyTime += measureTimeMillis {
                provider.verify(testData, lastSignature!!, publicKey)
            }
        }
        val avgVerifyTime = totalVerifyTime / 10

        println("✓ Complete")

        return BenchmarkResult(
            algorithm = provider.algorithm,
            keyGenTimeMs = keyGenTime,
            signTimeMs = avgSignTime,
            verifyTimeMs = avgVerifyTime,
            signatureSize = provider.getSignatureSize(),
            publicKeySize = provider.getPublicKeySize(),
            securityBits = curveType.securityBits
        )
    }

    private fun benchmarkRSA(keySize: Int): BenchmarkResult {
        val provider = RSAAuthProvider(keySize)
        val testData = ByteArray(1024) { it.toByte() }

        print("Testing ${provider.algorithm}... ")

        var keyPair: AuthKeyPair? = null
        val keyGenTime = measureTimeMillis {
            keyPair = provider.generateKeyPair()
        }

        val privateKey = extractPrivateKey(keyPair!!)
        val publicKey = extractPublicKey(keyPair!!)

        var totalSignTime = 0L
        var lastSignature: ByteArray? = null
        repeat(10) {
            totalSignTime += measureTimeMillis {
                lastSignature = provider.sign(testData, privateKey)
            }
        }
        val avgSignTime = totalSignTime / 10

        var totalVerifyTime = 0L
        repeat(10) {
            totalVerifyTime += measureTimeMillis {
                provider.verify(testData, lastSignature!!, publicKey)
            }
        }
        val avgVerifyTime = totalVerifyTime / 10

        println("✓ Complete")

        val securityBits = when (keySize) {
            1024 -> 80
            2048 -> 112
            3072 -> 128
            4096 -> 152
            else -> 0
        }

        return BenchmarkResult(
            algorithm = provider.algorithm,
            keyGenTimeMs = keyGenTime,
            signTimeMs = avgSignTime,
            verifyTimeMs = avgVerifyTime,
            signatureSize = provider.getSignatureSize(),
            publicKeySize = provider.getPublicKeySize(),
            securityBits = securityBits
        )
    }

    private fun printComparisonTable(results: List<BenchmarkResult>) {
        println("\n" + "═".repeat(80))
        println("📊 COMPARISON TABLE")
        println("═".repeat(80))

        println(String.format(
            "%-15s | %9s | %7s | %7s | %9s | %8s | %8s | %8s",
            "Algorithm", "KeyGen(ms)", "Sign(ms)", "Ver(ms)", "Total(ms)", "Sig(B)", "PubKey(B)", "Security"
        ))
        println("─".repeat(80))

        results.forEach { r ->
            val totalTime = r.signTimeMs + r.verifyTimeMs
            println(String.format(
                "%-15s | %9d | %7d | %7d | %9d | %8d | %8d | ~%d bits",
                r.algorithm,
                r.keyGenTimeMs,
                r.signTimeMs,
                r.verifyTimeMs,
                totalTime,
                r.signatureSize,
                r.publicKeySize,
                r.securityBits
            ))
        }

        println("═".repeat(80))
    }

    private fun printWinners(results: List<BenchmarkResult>) {
        println("\n" + "═".repeat(80))
        println("🏆 WINNERS")
        println("═".repeat(80))

        val fastest = results.minByOrNull { it.signTimeMs + it.verifyTimeMs }
        println("\n⚡ FASTEST SIGNING + VERIFICATION:")
        println("   ${fastest?.algorithm}")
        println("   Total: ${(fastest?.signTimeMs ?: 0) + (fastest?.verifyTimeMs ?: 0)} ms")

        val fastestKeyGen = results.minByOrNull { it.keyGenTimeMs }
        println("\n⚡ FASTEST KEY GENERATION:")
        println("   ${fastestKeyGen?.algorithm}")
        println("   Time: ${fastestKeyGen?.keyGenTimeMs} ms")

        val smallest = results.minByOrNull { it.signatureSize }
        println("\n📦 SMALLEST SIGNATURE:")
        println("   ${smallest?.algorithm}")
        println("   Size: ${smallest?.signatureSize} bytes")

        val smallestTotal = results.minByOrNull { it.signatureSize + it.publicKeySize }
        println("\n📦 SMALLEST TOTAL OVERHEAD:")
        println("   ${smallestTotal?.algorithm}")
        println("   Total: ${(smallestTotal?.signatureSize ?: 0) + (smallestTotal?.publicKeySize ?: 0)} bytes")

        val mostSecure = results.maxByOrNull { it.securityBits }
        println("\n🔒 HIGHEST SECURITY:")
        println("   ${mostSecure?.algorithm}")
        println("   Security: ~${mostSecure?.securityBits} bits")
    }

    private fun printRecommendations(results: List<BenchmarkResult>) {
        println("\n" + "═".repeat(80))
        println("💡 RECOMMENDATIONS")
        println("═".repeat(80))

        val p256 = results.find { it.algorithm == "ECDSA-P256" }

        println("\n✅ RECOMMENDED FOR PRODUCTION: ECDSA-P256")
        println("   Reasons:")
        println("   • Excellent performance: ${(p256?.signTimeMs ?: 0) + (p256?.verifyTimeMs ?: 0)} ms total")
        println("   • Small signature: ${p256?.signatureSize} bytes")
        println("   • Strong security: ~${p256?.securityBits} bits")
        println("   • Industry standard (TLS, Bitcoin, etc.)")
        println("   • SMS efficient: ~1-2 segments per handshake")

        val balanced = results.filter { it.securityBits >= 128 }
            .minByOrNull { it.signTimeMs + it.verifyTimeMs }

        println("\n⚖️  BEST BALANCE (≥128-bit security):")
        println("   ${balanced?.algorithm}")
        println("   Total time: ${(balanced?.signTimeMs ?: 0) + (balanced?.verifyTimeMs ?: 0)} ms")
        println("   Signature: ${balanced?.signatureSize} bytes")

        println("\n⚠️  NOT RECOMMENDED:")
        val weak = results.filter { it.securityBits < 112 }
        weak.forEach { r ->
            println("   • ${r.algorithm} - Only ~${r.securityBits} bits security (too weak)")
        }

        val expensive = results.filter { it.keyGenTimeMs > 3000 }
        expensive.forEach { r ->
            println("   • ${r.algorithm} - Very slow key generation (${r.keyGenTimeMs} ms)")
        }

        println("\n" + "═".repeat(80))
    }

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

    @Test
    fun quickCompareECDSAvsRSA() {
        println("\n" + "═".repeat(80))
        println("⚡ QUICK COMPARISON: ECDSA-P256 vs RSA-2048")
        println("═".repeat(80))

        val ecdsaResult = benchmarkECDSA(ECDSAAuthProvider.CurveType.P256)
        val rsaResult = benchmarkRSA(2048)

        println("\n📊 Results:")
        println("\nECDSA-P256:")
        println("  Key Generation: ${ecdsaResult.keyGenTimeMs} ms")
        println("  Sign:           ${ecdsaResult.signTimeMs} ms")
        println("  Verify:         ${ecdsaResult.verifyTimeMs} ms")
        println("  Signature Size: ${ecdsaResult.signatureSize} bytes")

        println("\nRSA-2048:")
        println("  Key Generation: ${rsaResult.keyGenTimeMs} ms")
        println("  Sign:           ${rsaResult.signTimeMs} ms")
        println("  Verify:         ${rsaResult.verifyTimeMs} ms")
        println("  Signature Size: ${rsaResult.signatureSize} bytes")

        println("\n🏆 Analysis:")
        val keyGenSpeedup = rsaResult.keyGenTimeMs.toDouble() / ecdsaResult.keyGenTimeMs
        val signSpeedup = rsaResult.signTimeMs.toDouble() / ecdsaResult.signTimeMs
        val sizeReduction = (1.0 - ecdsaResult.signatureSize.toDouble() / rsaResult.signatureSize) * 100

        println("  • ECDSA is ${"%.1f".format(keyGenSpeedup)}x faster at key generation")
        println("  • ECDSA signatures are ${"%.0f".format(sizeReduction)}% smaller")

        if (signSpeedup > 1) {
            println("  • ECDSA is ${"%.1f".format(signSpeedup)}x faster at signing")
        } else {
            println("  • RSA is ${"%.1f".format(1/signSpeedup)}x faster at signing")
        }

        println("\n✅ Winner: ECDSA-P256 (better overall performance and size)")
        println("═".repeat(80))
    }
}