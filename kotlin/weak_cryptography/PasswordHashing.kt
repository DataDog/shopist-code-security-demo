import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.util.HexFormat

class PasswordHashing {

    // VULN 1: MD5 for password hashing - user account passwords
    fun hashUserPassword(password: String): String {
        val md = MessageDigest.getInstance("MD5")
        val digest = md.digest(password.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    fun verifyUserPassword(inputPassword: String, storedHash: String): Boolean {
        return hashUserPassword(inputPassword) == storedHash
    }

    // VULN 2: SHA-1 for password hashing - legacy account migration
    fun hashLegacyPassword(password: String, username: String): String {
        val md = MessageDigest.getInstance("SHA-1")
        val input = "$username:$password"
        val digest = md.digest(input.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    // VULN 3: HmacMD5 for order integrity check
    fun computeOrderHmac(orderId: String, orderData: String, secretKey: String): String {
        val mac = Mac.getInstance("HmacMD5")
        val keySpec = SecretKeySpec(secretKey.toByteArray(Charsets.UTF_8), "HmacMD5")
        mac.init(keySpec)
        val digest = mac.doFinal(("$orderId:$orderData").toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }
}
