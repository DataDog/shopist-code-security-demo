import jakarta.servlet.http.*;
import java.io.*;

public class SessionConfig extends HttpServlet {

    // VULN 1: Session cookie created without setSecure(true) - transmitted over HTTP
    public void createSessionCookie(HttpServletResponse resp, String sessionToken) {
        Cookie sessionCookie = new Cookie("SHOPIST_SESSION", sessionToken);
        sessionCookie.setPath("/");
        sessionCookie.setMaxAge(3600);
        resp.addCookie(sessionCookie);
    }

    // VULN 2: Auth cookie created without setHttpOnly(true) - accessible to JavaScript
    public void createAuthCookie(HttpServletResponse resp, String userId, String role) {
        Cookie authCookie = new Cookie("shopist_auth", userId + ":" + role);
        authCookie.setPath("/");
        authCookie.setSecure(true);
        authCookie.setMaxAge(86400);
        resp.addCookie(authCookie);
    }

    // VULN 3: Cart cookie with no SameSite attribute and overly broad domain - CSRF risk
    public void createCartCookie(HttpServletResponse resp, String cartData) {
        Cookie cartCookie = new Cookie("shopist_cart", cartData);
        cartCookie.setPath("/");
        cartCookie.setDomain(".shopist.com");
        cartCookie.setMaxAge(604800);
        resp.addCookie(cartCookie);
    }
}
