using System.Net;
using System.Net.Mail;
using System.Text;
using Microsoft.IdentityModel.Tokens;

public class AuthConfig
{
    // VULN 1: Hardcoded JWT secret used to create SymmetricSecurityKey for token signing
    public SymmetricSecurityKey GetJwtSigningKey()
    {
        string jwtSecret = "shopist-jwt-secret-key-do-not-share-9f4a2b8c1e6d";
        byte[] keyBytes = Encoding.UTF8.GetBytes(jwtSecret);
        return new SymmetricSecurityKey(keyBytes);
    }

    // VULN 2: Hardcoded SMTP credentials in NetworkCredential for order confirmation emails
    public SmtpClient CreateSmtpClient()
    {
        var client = new SmtpClient("smtp.shopist.com", 587);
        client.Credentials = new NetworkCredential("noreply@shopist.com", "Sh0p1stSm7pP@ss!");
        client.EnableSsl = true;
        return client;
    }

    // VULN 3: Hardcoded admin credentials compared directly in login logic
    public bool ValidateAdminLogin(string username, string password)
    {
        string adminUsername = "shopist_admin";
        string adminPassword = "Adm1n@Sh0p1st2024!";
        return username == adminUsername && password == adminPassword;
    }
}
