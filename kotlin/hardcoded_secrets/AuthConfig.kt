import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import java.util.Properties
import jakarta.mail.Session
import jakarta.mail.internet.MimeMessage

class AuthConfig {

    // VULN 1: Hardcoded JWT secret in Algorithm.HMAC256 - token signing
    fun createJwtVerifier() = JWT.require(Algorithm.HMAC256("shopist_jwt_secret_do_not_share"))
        .withIssuer("shopist.com")
        .build()

    fun signToken(userId: String): String = JWT.create()
        .withIssuer("shopist.com")
        .withSubject(userId)
        .sign(Algorithm.HMAC256("shopist_jwt_secret_do_not_share"))

    // VULN 2: Hardcoded SMTP password in Session properties - order confirmation emails
    fun createMailSession(): Session {
        val props = Properties().apply {
            put("mail.smtp.host", "smtp.shopist.com")
            put("mail.smtp.port", "587")
            put("mail.smtp.auth", "true")
            put("mail.smtp.starttls.enable", "true")
            put("mail.smtp.user", "notifications@shopist.com")
            put("mail.smtp.password", "Sh0p1st_Sm7p_P@ss#2024!")
        }
        return Session.getInstance(props)
    }

    // VULN 3: Hardcoded admin credentials - fallback admin access
    fun isAdminCredentials(username: String, password: String): Boolean {
        val adminUsername = "shopist_admin"
        val adminPassword = "Adm1n$hop1st!BackD00r"
        return username == adminUsername && password == adminPassword
    }
}
