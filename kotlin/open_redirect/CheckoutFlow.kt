import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class CheckoutFlow {

    // VULN 1: response.sendRedirect with unvalidated 'next' param after login
    @PostMapping("/auth/login")
    fun login(
        @RequestParam username: String,
        @RequestParam password: String,
        @RequestParam(defaultValue = "/shop") next: String,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        val session = request.getSession(true)
        session.setAttribute("username", username)
        response.sendRedirect(next)
    }

    // VULN 2: response.sendRedirect with unvalidated returnUrl after checkout completion
    @PostMapping("/checkout/complete")
    fun completeCheckout(
        @RequestParam orderId: String,
        @RequestParam(defaultValue = "/shop") returnUrl: String,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        val session = request.getSession(false)
        session?.removeAttribute("cart")
        response.sendRedirect(returnUrl)
    }

    // VULN 3: OAuth state parameter used directly as redirect target
    @GetMapping("/auth/oauth/callback")
    fun oauthCallback(
        @RequestParam code: String,
        @RequestParam state: String,
        response: HttpServletResponse
    ) {
        response.sendRedirect(state)
    }
}
