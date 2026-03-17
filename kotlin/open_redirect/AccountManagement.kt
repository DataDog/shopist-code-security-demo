import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class AccountManagement {

    // VULN 1: response.sendRedirect with unvalidated redirectTo in password reset flow
    @GetMapping("/account/reset-password/confirm")
    fun confirmPasswordReset(
        @RequestParam token: String,
        @RequestParam newPassword: String,
        @RequestParam(defaultValue = "/account/login") redirectTo: String,
        response: HttpServletResponse
    ) {
        response.sendRedirect(redirectTo)
    }

    // VULN 2: Referer header used directly as redirect target after logout
    @PostMapping("/auth/logout")
    fun logout(
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        request.getSession(false)?.invalidate()
        val referer = request.getHeader("Referer") ?: "/shop"
        response.sendRedirect(referer)
    }

    // VULN 3: callback_url param used directly as redirect for social account linking
    @GetMapping("/account/social/link/callback")
    fun socialLinkCallback(
        @RequestParam provider: String,
        @RequestParam code: String,
        @RequestParam(defaultValue = "/account/settings") callback_url: String,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        val session = request.getSession(false)
        session?.setAttribute("${provider}_linked", true)
        response.sendRedirect(callback_url)
    }
}
