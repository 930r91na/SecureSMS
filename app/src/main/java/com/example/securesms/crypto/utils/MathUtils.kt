package com.example.securesms.crypto.utils

import android.os.Build
import androidx.annotation.RequiresApi
import java.math.BigInteger

object MathUtils {

    /**
     * Extended Euclidean Algorithm for finding GCD and Bézout coefficients
     * Returns Triple(gcd, x, y) where gcd = a*x + b*y
     */
    fun extendedGCD(a: BigInteger, b: BigInteger): Triple<BigInteger, BigInteger, BigInteger> {
        if (b == BigInteger.ZERO) {
            return Triple(a, BigInteger.ONE, BigInteger.ZERO)
        }

        val (gcd, x1, y1) = extendedGCD(b, a % b)
        val x = y1
        val y = x1 - (a / b) * y1

        return Triple(gcd, x, y)
    }

    /**
     * Calculate modular inverse: a^-1 mod m
     * Based on your cybersecurity notes
     */
    fun modularInverse(a: BigInteger, m: BigInteger): BigInteger {
        val (gcd, x, _) = extendedGCD(a % m, m)

        if (gcd != BigInteger.ONE) {
            throw ArithmeticException("Modular inverse does not exist: gcd($a, $m) = $gcd")
        }

        // Ensure positive result
        return ((x % m) + m) % m
    }

    /**
     * Modular exponentiation: base^exp mod modulus
     * Efficient implementation for large numbers
     */
    fun modPow(base: BigInteger, exp: BigInteger, modulus: BigInteger): BigInteger {
        return base.modPow(exp, modulus)
    }

    /**
     * Calculate GCD using Euclidean algorithm
     */
    fun gcd(a: BigInteger, b: BigInteger): BigInteger {
        return a.gcd(b)
    }

    /**
     * Calculate Euler's totient function φ(n) for n = p * q
     * where p and q are primes
     */
    fun eulerTotient(p: BigInteger, q: BigInteger): BigInteger {
        return (p - BigInteger.ONE) * (q - BigInteger.ONE)
    }


    /**
     * Simple prime factorization (for small numbers in DH setup)
     */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun primeFactorize(n: BigInteger): Set<BigInteger> {
        val factors = mutableSetOf<BigInteger>()
        var num = n
        var divisor = BigInteger.TWO

        while (divisor * divisor <= num) {
            while (num % divisor == BigInteger.ZERO) {
                factors.add(divisor)
                num /= divisor
            }
            divisor += BigInteger.ONE
        }

        if (num > BigInteger.ONE) {
            factors.add(num)
        }

        return factors
    }
}