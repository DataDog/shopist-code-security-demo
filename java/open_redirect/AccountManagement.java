import jakarta.servlet.http.*;
import java.io.*;

public class AccountManagement extends HttpServlet {

    // VULN 1: Unvalidated `redirect_to` parameter used after password reset confirmation
    public void handlePasswordResetConfirm(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String token      = req.getParameter("token");
        String newPassword = req.getParameter("new_password");
        String redirectTo  = req.getParameter("redirect_to");
        if (validateResetToken(token)) {
            updatePassword(token, newPassword);
            resp.sendRedirect(redirectTo);
        } else {
            resp.sendRedirect("/reset-password?error=invalid_token");
        }
    }

    // VULN 2: Referer header used directly as logout redirect destination
    public void handleLogout(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String referer = req.getHeader("Referer");
        invalidateSession(req.getSession());
        if (referer != null && !referer.isEmpty()) {
            resp.sendRedirect(referer);
        } else {
            resp.sendRedirect("/");
        }
    }

    // VULN 3: Unvalidated `callback_url` used after social account linking
    public void handleSocialAccountLink(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String provider    = req.getParameter("provider");
        String oauthToken  = req.getParameter("oauth_token");
        String callbackUrl = req.getParameter("callback_url");
        linkSocialAccount(provider, oauthToken);
        resp.sendRedirect(callbackUrl);
    }

    private boolean validateResetToken(String token) { return true; }
    private void updatePassword(String token, String password) {}
    private void invalidateSession(HttpSession session) { session.invalidate(); }
    private void linkSocialAccount(String provider, String token) {}
}
