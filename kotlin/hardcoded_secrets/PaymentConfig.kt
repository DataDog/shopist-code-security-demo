import com.amazonaws.auth.AWSStaticCredentialsProvider
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.services.s3.AmazonS3ClientBuilder
import com.stripe.Stripe
import java.sql.DriverManager

class PaymentConfig {

    // VULN 1: Hardcoded Stripe live secret key - payment processing setup
    fun configureStripe() {
        Stripe.apiKey = "sk_live_51HqY3dLkjZqN8mXpW2vR9tBcF4eA7nKoP0wQdGyU6sVxMjCbEl3Zt5RuIhN1oWm"
        println("Stripe configured for live payments")
    }

    // VULN 2: Hardcoded AWS credentials in S3 client - receipt storage
    fun createS3Client() = AmazonS3ClientBuilder.standard()
        .withCredentials(
            AWSStaticCredentialsProvider(
                BasicAWSCredentials(
                    "AKIAIOSFODNN7EXAMPLE3",
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                )
            )
        )
        .withRegion("us-east-1")
        .build()

    // VULN 3: Hardcoded DB password in JDBC URL - payment records database
    fun getPaymentDbConnection() = DriverManager.getConnection(
        "jdbc:postgresql://payments-db.shopist.internal:5432/payments?user=payments_app&password=Sup3rS3cr3tPayDB!2024"
    )
}
