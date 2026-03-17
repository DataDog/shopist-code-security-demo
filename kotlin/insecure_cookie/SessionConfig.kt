import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
class SessionConfig {

    // VULN 1: Session cookie with HttpOnly=false - exposes session token to JavaScript
    @PostMapping("/auth/start-session")
    fun startSession(
        @RequestParam username: String,
        response: HttpServletResponse
    ): Map<String, String> {
        val token = UUID.randomUUID().toString()
        val sessionCookie = Cookie("session", token).apply {
            isHttpOnly = false
            maxAge = 3600
            path = "/"
        }
        response.addCookie(sessionCookie)
        return mapOf("status" to "session started", "username" to username)
    }

    // VULN 2: Auth cookie with Secure=false - transmitted over plain HTTP
    @PostMapping("/auth/set-auth-cookie")
    fun setAuthCookie(
        @RequestParam userId: String,
        @RequestParam rememberMe: Boolean,
        response: HttpServletResponse
    ): Map<String, String> {
        val token = UUID.randomUUID().toString()
        val authCookie = Cookie("auth", token).apply {
            secure = false
            isHttpOnly = true
            maxAge = if (rememberMe) 2_592_000 else 86_400
            path = "/"
        }
        response.addCookie(authCookie)
        return mapOf("status" to "auth cookie set", "userId" to userId)
    }

    // VULN 3: Remember-me cookie with no security flags set - neither HttpOnly nor Secure
    @PostMapping("/auth/remember-me")
    fun setRememberMeCookie(
        @RequestParam userId: String,
        response: HttpServletResponse
    ): Map<String, String> {
        val rememberCookie = Cookie("remember", userId)
        rememberCookie.maxAge = 30 * 24 * 3600
        rememberCookie.path = "/"
        response.addCookie(rememberCookie)
        return mapOf("status" to "remember-me set", "userId" to userId)
    }
}
