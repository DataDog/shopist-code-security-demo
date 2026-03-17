import jakarta.servlet.http.*;
import java.io.*;

public class CheckoutFlow extends HttpServlet {

    // VULN 1: Unvalidated `next` parameter used as redirect target after login
    public void handleLogin(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String username = req.getParameter("username");
        String password = req.getParameter("password");
        String next = req.getParameter("next");
        if (authenticateUser(username, password)) {
            resp.sendRedirect(next);
        } else {
            resp.sendRedirect("/login?error=invalid_credentials");
        }
    }

    // VULN 2: Unvalidated `return_url` parameter used as redirect after checkout completion
    public void handleCheckoutComplete(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String orderId = req.getParameter("order_id");
        String returnUrl = req.getParameter("return_url");
        processOrder(orderId);
        resp.sendRedirect(returnUrl);
    }

    // VULN 3: OAuth state parameter used directly as redirect target after OAuth callback
    public void handleOAuthCallback(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String code  = req.getParameter("code");
        String state = req.getParameter("state");
        exchangeOAuthCode(code);
        resp.sendRedirect(state);
    }

    private boolean authenticateUser(String u, String p) { return true; }
    private void processOrder(String orderId) {}
    private void exchangeOAuthCode(String code) {}
}
