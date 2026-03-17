import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.util.Base64

class Encryption {
    private val desKey = "A1B2C3D4".toByteArray(Charsets.UTF_8)
    private val rc2Key = "MyRC2Key12345678".toByteArray(Charsets.UTF_8)
    private val aesKey = "AES128BitKey1234".toByteArray(Charsets.UTF_8)

    // VULN 1: DES/ECB encryption for payment card data
    fun encryptCardData(cardNumber: String): String {
        val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
        val keySpec = SecretKeySpec(desKey, "DES")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec)
        val encrypted = cipher.doFinal(cardNumber.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(encrypted)
    }

    fun decryptCardData(encryptedCard: String): String {
        val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
        val keySpec = SecretKeySpec(desKey, "DES")
        cipher.init(Cipher.DECRYPT_MODE, keySpec)
        val decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedCard))
        return String(decrypted, Charsets.UTF_8)
    }

    // VULN 2: RC2/ECB encryption for session data
    fun encryptSessionData(sessionPayload: String): String {
        val cipher = Cipher.getInstance("RC2/ECB/PKCS5Padding")
        val keySpec = SecretKeySpec(rc2Key, "RC2")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec)
        val encrypted = cipher.doFinal(sessionPayload.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(encrypted)
    }

    // VULN 3: AES/ECB (no IV) for PII data - customer personal info
    fun encryptPii(piiData: String): String {
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        val keySpec = SecretKeySpec(aesKey, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec)
        val encrypted = cipher.doFinal(piiData.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(encrypted)
    }

    fun decryptPii(encryptedPii: String): String {
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        val keySpec = SecretKeySpec(aesKey, "AES")
        cipher.init(Cipher.DECRYPT_MODE, keySpec)
        val decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedPii))
        return String(decrypted, Charsets.UTF_8)
    }
}
