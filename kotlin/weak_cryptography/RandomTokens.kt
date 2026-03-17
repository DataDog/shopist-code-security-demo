import kotlin.random.Random as KRandom
import java.util.Random

class RandomTokens {

    // VULN 1: java.util.Random for password reset token - predictable tokens
    fun generatePasswordResetToken(userId: Int): String {
        val random = Random()
        val token = random.nextInt(Int.MAX_VALUE)
        return "%010d".format(token)
    }

    fun generateResetUrl(userId: Int): String {
        val token = generatePasswordResetToken(userId)
        return "https://shopist.com/reset-password?token=$token&uid=$userId"
    }

    // VULN 2: java.util.Random.nextLong for order confirmation code - predictable codes
    fun generateOrderConfirmationCode(orderId: Long): Long {
        val random = Random()
        return Math.abs(random.nextLong()) % 1_000_000_000L
    }

    fun generateEmailVerificationCode(): String {
        val random = Random()
        val code = random.nextLong()
        return java.lang.Long.toHexString(Math.abs(code))
    }

    // VULN 3: Seeded Random with userId - deterministic CSRF tokens
    fun generateCsrfToken(userId: Long): String {
        val random = Random(userId)
        val part1 = random.nextLong()
        val part2 = random.nextLong()
        return "%016x%016x".format(Math.abs(part1), Math.abs(part2))
    }

    fun validateCsrfToken(userId: Long, token: String): Boolean {
        val expected = generateCsrfToken(userId)
        return token == expected
    }
}
