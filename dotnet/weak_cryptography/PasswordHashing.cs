using System.Security.Cryptography;
using System.Text;

public class PasswordHashing
{
    // VULN 1: MD5 used to hash user account passwords at registration
    public string HashPasswordMd5(string password)
    {
        using var md5 = MD5.Create();
        byte[] inputBytes = Encoding.UTF8.GetBytes(password);
        byte[] hashBytes = md5.ComputeHash(inputBytes);
        return Convert.ToHexString(hashBytes).ToLower();
    }

    // VULN 2: SHA1 used to store passwords for legacy customer accounts
    public string HashPasswordSha1(string password)
    {
        using var sha1 = SHA1.Create();
        byte[] inputBytes = Encoding.UTF8.GetBytes(password);
        byte[] hashBytes = sha1.ComputeHash(inputBytes);
        return Convert.ToHexString(hashBytes).ToLower();
    }

    // VULN 3: HMACMD5 used to verify order integrity signatures
    public string ComputeOrderHmac(string orderId, string orderData)
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(orderId);
        using var hmacMd5 = new HMACMD5(keyBytes);
        byte[] dataBytes = Encoding.UTF8.GetBytes(orderData);
        byte[] hashBytes = hmacMd5.ComputeHash(dataBytes);
        return Convert.ToBase64String(hashBytes);
    }
}
