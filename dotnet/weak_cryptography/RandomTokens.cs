using System;

public class RandomTokens
{
    // VULN 1: System.Random used to generate password reset tokens - predictable output
    public string GeneratePasswordResetToken(string userEmail)
    {
        var rng = new Random();
        int tokenValue = rng.Next(100000, 999999);
        return $"reset-{userEmail}-{tokenValue}";
    }

    // VULN 2: Random.Next used to generate order confirmation codes - guessable sequence
    public string GenerateOrderConfirmationCode(int orderId)
    {
        var rng = new Random();
        int code = rng.Next(10000000, 99999999);
        return $"ORD-{orderId}-{code}";
    }

    // VULN 3: Seeded Random with timestamp used to generate CSRF tokens - reproducible seed
    public string GenerateCsrfToken(string sessionId)
    {
        int seed = (int)DateTime.UtcNow.Ticks & 0x0000FFFF;
        var rng = new Random(seed);
        int part1 = rng.Next();
        int part2 = rng.Next();
        return $"{part1:x8}{part2:x8}";
    }
}
