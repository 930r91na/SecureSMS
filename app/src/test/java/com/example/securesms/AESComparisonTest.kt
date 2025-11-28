package com.example.securesms.crypto.test

import android.os.Build
import androidx.annotation.RequiresApi
import com.example.securesms.crypto.symmetric.AES
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import kotlin.system.measureTimeMillis

/**
 * Performance Benchmark Tests for AES
 *
 * Run these tests from Android Studio:
 * Right-click on the test class → Run 'AESPerformanceTest'
 *
 * Tests all AES key sizes:
 * - AES-128, AES-192, AES-256
 *
 * Mode: GCM (Galois/Counter Mode)
 * - Provides both encryption and authentication
 *
 * Measures:
 * - Encryption time (average of 100 iterations)
 * - Decryption time (average of 100 iterations)
 * - Overhead size (IV + authentication tag)
 */
@RunWith(Parameterized::class)
class AESPerformanceTest(
    private val keySize: Int,
    private val algorithmName: String
) {

    companion object {
        private const val ITERATIONS = 100
        private const val TEST_DATA_SIZE = 1024 // 1KB

        @JvmStatic
        @Parameterized.Parameters(name = "{1}")
        fun data(): Collection<Array<Any>> {
            return listOf(
                arrayOf(AES.KEY_SIZE_128, "AES-128-GCM"),
                arrayOf(AES.KEY_SIZE_192, "AES-192-GCM"),
                arrayOf(AES.KEY_SIZE_256, "AES-256-GCM")
            )
        }
    }

    @Test
    fun benchmarkAES() {
        println("\n" + "=".repeat(70))
        println("🔐 AES PERFORMANCE BENCHMARK: $algorithmName")
        println("=".repeat(70))

        val aes = AES()
        val testData = ByteArray(TEST_DATA_SIZE) { it.toByte() }

        // === KEY GENERATION ===
        println("\n📊 Key Generation:")
        var key: javax.crypto.SecretKey? = null
        val keyGenTime = measureTimeMillis {
            key = AES.generateKey(keySize)
        }
        println("   Time: $keyGenTime ms (negligible)")
        println("   Key Size: ${keySize / 8} bytes")

        // === ENCRYPTION ===
        println("\n📊 Encryption ($ITERATIONS iterations):")
        var lastEncrypted: AES.EncryptedMessage? = null
        val encryptTimes = mutableListOf<Long>()

        repeat(ITERATIONS) {
            val time = measureTimeMillis {
                lastEncrypted = aes.encrypt(testData, key!!)
            }
            encryptTimes.add(time)
        }

        val avgEncryptTime = encryptTimes.average()
        val minEncryptTime = encryptTimes.minOrNull() ?: 0
        val maxEncryptTime = encryptTimes.maxOrNull() ?: 0

        println("   Average: ${"%.2f".format(avgEncryptTime)} ms")
        println("   Min:     $minEncryptTime ms")
        println("   Max:     $maxEncryptTime ms")

        // === DECRYPTION ===
        println("\n📊 Decryption ($ITERATIONS iterations):")
        val decryptTimes = mutableListOf<Long>()

        repeat(ITERATIONS) {
            val time = measureTimeMillis {
                val decrypted = aes.decrypt(lastEncrypted!!, key!!)
                assert(decrypted.contentEquals(testData)) { "Decrypted data should match original" }
            }
            decryptTimes.add(time)
        }

        val avgDecryptTime = decryptTimes.average()
        val minDecryptTime = decryptTimes.minOrNull() ?: 0
        val maxDecryptTime = decryptTimes.maxOrNull() ?: 0

        println("   Average: ${"%.2f".format(avgDecryptTime)} ms")
        println("   Min:     $minDecryptTime ms")
        println("   Max:     $maxDecryptTime ms")

        // === SUMMARY ===
        println("\n📊 Summary:")
        println("   Total Time (Encrypt + Decrypt): ${"%.2f".format(avgEncryptTime + avgDecryptTime)} ms")

        val overhead = lastEncrypted!!.ciphertext.size - testData.size
        println("   Overhead: $overhead bytes (IV + auth tag)")
        println("   Ciphertext Size: ${lastEncrypted!!.ciphertext.size} bytes")
        println("   Original Size: ${testData.size} bytes")

        val throughputMBps = (TEST_DATA_SIZE / 1024.0 / 1024.0) / ((avgEncryptTime + avgDecryptTime) / 1000.0)
        println("   Throughput: ${"%.2f".format(throughputMBps)} MB/s")

        println("\n" + "=".repeat(70))
    }
}