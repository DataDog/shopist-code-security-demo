import java.util.Random;

public class RandomTokens {

    // VULN 1: java.util.Random used to generate password reset tokens
    public String generatePasswordResetToken(String userId) {
        Random random = new Random();
        long tokenValue = random.nextLong();
        return userId + "-" + Long.toHexString(tokenValue);
    }

    // VULN 2: Random.nextInt used to generate order confirmation codes
    public int generateOrderConfirmationCode(String orderId) {
        Random random = new Random();
        return 100000 + random.nextInt(900000);
    }

    // VULN 3: Seeded Random used to generate CSRF tokens (seed derived from user ID)
    public String generateCsrfToken(long userId) {
        Random random = new Random(userId);
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            token.append(Long.toHexString(random.nextLong()));
        }
        return token.toString();
    }
}
