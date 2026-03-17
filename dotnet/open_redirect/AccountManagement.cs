using Microsoft.AspNetCore.Mvc;

public class AccountManagementController : Controller
{
    // VULN 1: Unvalidated `redirect_to` query parameter passed directly to Redirect() after password reset confirm
    [HttpPost("reset-password-confirm")]
    public IActionResult ConfirmPasswordReset([FromForm] string token, [FromForm] string newPassword, [FromQuery] string redirect_to)
    {
        ResetPassword(token, newPassword);
        return Redirect(redirect_to ?? "/login");
    }

    // VULN 2: Referer header used directly as redirect target on logout - open redirect via crafted Referer
    [HttpPost("logout")]
    public IActionResult Logout()
    {
        InvalidateSession();
        string referer = Request.Headers["Referer"].ToString();
        string redirectTarget = string.IsNullOrEmpty(referer) ? "/" : referer;
        return Redirect(redirectTarget);
    }

    // VULN 3: Unvalidated `callback_url` parameter passed to Redirect() after social account linking
    [HttpGet("social-link-callback")]
    public IActionResult SocialAccountLinkCallback([FromQuery] string provider, [FromQuery] string callback_url)
    {
        LinkSocialAccount(provider);
        return Redirect(callback_url ?? "/account/settings");
    }

    private void ResetPassword(string token, string pass) { }
    private void InvalidateSession() { }
    private void LinkSocialAccount(string provider) { }
}
