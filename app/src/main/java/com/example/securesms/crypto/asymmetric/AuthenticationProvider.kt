import com.example.securesms.crypto.models.ECCKeyPair
import com.example.securesms.crypto.models.ECCPrivateKey
import com.example.securesms.crypto.models.ECCPublicKey
import com.example.securesms.crypto.models.RSAKeyPair
import com.example.securesms.crypto.models.RSAPrivateKey
import com.example.securesms.crypto.models.RSAPublicKey

public interface AuthenticationProvider {
    val algorithm: String
    val keySize: Int

    fun generateKeyPair(): AuthKeyPair
    fun sign(data: ByteArray, privateKey: AuthPrivateKey): ByteArray
    fun verify(data: ByteArray, signature: ByteArray, publicKey: AuthPublicKey): Boolean
    fun getPublicKeySize(): Int
    fun getSignatureSize(): Int
}

/**
 * Generic auth key wrappers
 */
sealed class AuthKeyPair {
    data class RSAAuth(val keyPair: RSAKeyPair) : AuthKeyPair()
    data class ECDSAAuth(val keyPair: ECCKeyPair) : AuthKeyPair()
}

sealed class AuthPublicKey {
    data class RSAAuth(val key: RSAPublicKey) : AuthPublicKey()
    data class ECDSAAuth(val key: ECCPublicKey) : AuthPublicKey()
}

sealed class AuthPrivateKey {
    data class RSAAuth(val key: RSAPrivateKey) : AuthPrivateKey()
    data class ECDSAAuth(val key: ECCPrivateKey) : AuthPrivateKey()
}