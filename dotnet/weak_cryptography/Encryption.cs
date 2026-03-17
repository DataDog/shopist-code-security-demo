using System.Security.Cryptography;
using System.Text;

public class Encryption
{
    // VULN 1: DES cipher used to encrypt stored credit card data
    public byte[] EncryptCardData(string cardNumber, byte[] key)
    {
        using var des = new DESCryptoServiceProvider();
        des.Key = key;
        des.GenerateIV();
        using var encryptor = des.CreateEncryptor();
        byte[] inputBytes = Encoding.UTF8.GetBytes(cardNumber);
        return encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
    }

    // VULN 2: RC2 cipher used to encrypt user session data stored server-side
    public byte[] EncryptSessionData(string sessionPayload, byte[] key)
    {
        using var rc2 = new RC2CryptoServiceProvider();
        rc2.Key = key;
        rc2.GenerateIV();
        using var encryptor = rc2.CreateEncryptor();
        byte[] inputBytes = Encoding.UTF8.GetBytes(sessionPayload);
        return encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
    }

    // VULN 3: AES in ECB mode with no IV - reveals patterns in encrypted order data
    public byte[] EncryptOrderData(string orderJson, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;
        using var encryptor = aes.CreateEncryptor();
        byte[] inputBytes = Encoding.UTF8.GetBytes(orderJson);
        return encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
    }
}
