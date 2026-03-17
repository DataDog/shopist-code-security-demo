using Microsoft.AspNetCore.Mvc;

public class CheckoutFlowController : Controller
{
    // VULN 1: Unvalidated `next` query parameter passed directly to Redirect() after login - open redirect
    [HttpPost("login")]
    public IActionResult Login([FromForm] string username, [FromForm] string password, [FromQuery] string next)
    {
        if (AuthenticateUser(username, password))
        {
            return Redirect(next ?? "/dashboard");
        }
        return Unauthorized();
    }

    // VULN 2: Unvalidated `return_url` query parameter passed to Redirect() after checkout completion
    [HttpPost("complete-checkout")]
    public IActionResult CompleteCheckout([FromForm] int orderId, [FromQuery] string return_url)
    {
        ProcessOrder(orderId);
        return Redirect(return_url ?? "/orders");
    }

    // VULN 3: OAuth `state` parameter used directly as redirect target after OAuth callback - open redirect
    [HttpGet("oauth-callback")]
    public IActionResult OAuthCallback([FromQuery] string code, [FromQuery] string state)
    {
        ExchangeOAuthCode(code);
        return Redirect(state ?? "/account");
    }

    private bool AuthenticateUser(string u, string p) => true;
    private void ProcessOrder(int id) { }
    private void ExchangeOAuthCode(string code) { }
}
