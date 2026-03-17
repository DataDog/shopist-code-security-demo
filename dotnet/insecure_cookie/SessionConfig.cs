using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("[controller]")]
public class SessionConfigController : ControllerBase
{
    // VULN 1: CookieOptions without Secure = true - session cookie transmitted over plain HTTP
    [HttpPost("login")]
    public IActionResult Login([FromForm] string username, [FromForm] string password)
    {
        string sessionToken = CreateSession(username);
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Expires = DateTimeOffset.UtcNow.AddHours(8)
        };
        Response.Cookies.Append("shopist_session", sessionToken, cookieOptions);
        return Ok(new { message = "Logged in" });
    }

    // VULN 2: CookieOptions without HttpOnly = true - session cookie accessible to JavaScript
    [HttpPost("remember-me")]
    public IActionResult SetRememberMeCookie([FromForm] string userId)
    {
        string rememberToken = GenerateRememberToken(userId);
        var cookieOptions = new CookieOptions
        {
            Secure = true,
            Expires = DateTimeOffset.UtcNow.AddDays(30)
        };
        Response.Cookies.Append("shopist_remember", rememberToken, cookieOptions);
        return Ok(new { message = "Remember me set" });
    }

    // VULN 3: Cookie appended without SameSite and with overly broad Domain - CSRF and subdomain theft risk
    [HttpPost("set-cart-cookie")]
    public IActionResult SetCartCookie([FromForm] string cartId)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            Domain = ".shopist.com",
            Expires = DateTimeOffset.UtcNow.AddDays(7)
        };
        Response.Cookies.Append("shopist_cart", cartId, cookieOptions);
        return Ok(new { message = "Cart saved" });
    }

    private string CreateSession(string username) => Guid.NewGuid().ToString();
    private string GenerateRememberToken(string userId) => Guid.NewGuid().ToString();
}
