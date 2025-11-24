package com.example.securesms.crypto.test

import com.example.securesms.crypto.asymmetric.ECC
import com.example.securesms.crypto.models.*
import java.math.BigInteger

/**
 * Test ECC implementation
 */
fun main() {
    println("=".repeat(60))
    println("ECC IMPLEMENTATION TEST")
    println("=".repeat(60))

    val ecc = ECC()

    // Test 1: Small curve from notebook example
    println("\n--- Test 1: Small Test Curve (mod 17) ---")
    testSmallCurve(ecc)

    // Test 2: ECDH Key Exchange
    println("\n--- Test 2: ECDH Key Exchange ---")
    testECDH(ecc)

    // Test 3: Encryption/Decryption
    println("\n--- Test 3: Encryption & Decryption ---")
    testEncryption(ecc)

    println("\n" + "=".repeat(60))
    println("ALL TESTS COMPLETED")
    println("=".repeat(60))
}

fun testSmallCurve(ecc: ECC) {
    val curve = ECC.getTestCurve()
    println("Curve: ${curve.toCompactString()}")
    println("Generator G: ${curve.G}")
    println("Order n: ${curve.n}")

    // Test point doubling: 2P
    val P = curve.G
    val twoP = ecc.pointAdd(P, P, curve)
    println("\n2P = P + P = $twoP")

    // Test scalar multiplication: 3P
    val threeP = ecc.scalarMultiply(P, BigInteger.valueOf(3), curve)
    println("3P = $threeP")

    // Verify point is on curve
    val onCurve = ecc.verifyPoint(threeP, curve)
    println("Point 3P is on curve: $onCurve")

    if (onCurve) {
        println("✓ Point operations working correctly")
    } else {
        println("✗ Point operations failed")
    }
}

fun testECDH(ecc: ECC) {
    val curve = ECC.getTestCurve()

    // Alice's keys
    val alicePrivate = BigInteger.valueOf(3)
    val aliceKeyPair = ECC.generateKeyPairFromPrivate(alicePrivate, curve)
    println("Alice:")
    println("  Private key (a): ${aliceKeyPair.privateKey.d}")
    println("  Public key (A): ${aliceKeyPair.publicKey.Q}")

    // Bob's keys
    val bobPrivate = BigInteger.valueOf(5)
    val bobKeyPair = ECC.generateKeyPairFromPrivate(bobPrivate, curve)
    println("\nBob:")
    println("  Private key (b): ${bobKeyPair.privateKey.d}")
    println("  Public key (B): ${bobKeyPair.publicKey.Q}")

    // Alice computes shared secret: S = a·B
    val aliceShared = ecc.generateSharedSecret(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
    )
    println("\nAlice computes: S = a·B = $aliceShared")

    // Bob computes shared secret: S = b·A
    val bobShared = ecc.generateSharedSecret(
        bobKeyPair.privateKey,
        aliceKeyPair.publicKey
    )
    println("Bob computes: S = b·A = $bobShared")

    // Verify they match
    if (aliceShared == bobShared) {
        println("\n✓ ECDH successful! Shared secrets match")
    } else {
        println("\n✗ ECDH failed! Shared secrets don't match")
    }
}

fun testEncryption(ecc: ECC) {
    val curve = ECC.getTestCurve()

    // Generate Bob's key pair (recipient)
    val bobKeyPair = ECC.generateKeyPair(curve)
    println("Bob's public key: ${bobKeyPair.publicKey.Q.toCompactString()}")

    // Original message
    val message = "Hello ECC!"
    println("\nOriginal message: \"$message\"")

    // Alice encrypts for Bob
    val encrypted = ecc.encrypt(message, bobKeyPair.publicKey)
    println("\nEncrypted:")
    println("  R (ephemeral): ${encrypted.R.toCompactString()}")
    println("  Ciphertext: ${encrypted.ciphertext.size} bytes")

    // Bob decrypts
    val decrypted = ecc.decrypt(encrypted, bobKeyPair.privateKey)
    println("\nDecrypted message: \"$decrypted\"")

    // Verify
    if (decrypted == message) {
        println("\n✓ Encryption/Decryption successful!")
    } else {
        println("\n✗ Encryption/Decryption failed!")
    }
}