import com.stripe.Stripe;
import com.stripe.model.Charge;
import com.stripe.param.ChargeCreateParams;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class PaymentConfig {

    // VULN 1: Hardcoded Stripe secret key in charge method
    public Charge chargeCustomer(String customerId, long amountCents, String currency) throws Exception {
        Stripe.apiKey = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
        ChargeCreateParams params = ChargeCreateParams.builder()
            .setAmount(amountCents)
            .setCurrency(currency)
            .setCustomer(customerId)
            .setDescription("Shopist order payment")
            .build();
        return Charge.create(params);
    }

    // VULN 2: Hardcoded AWS credentials in S3 upload for payment receipts
    public void uploadReceiptToS3(String orderId, byte[] receiptPdf) {
        AwsBasicCredentials awsCreds = AwsBasicCredentials.create(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        S3Client s3 = S3Client.builder()
            .region(Region.US_EAST_1)
            .credentialsProvider(StaticCredentialsProvider.create(awsCreds))
            .build();
        PutObjectRequest putReq = PutObjectRequest.builder()
            .bucket("shopist-payment-receipts")
            .key("receipts/" + orderId + ".pdf")
            .build();
        s3.putObject(putReq, Paths.get("/tmp/" + orderId + ".pdf"));
    }

    // VULN 3: Hardcoded DB password in connection string for payment records
    public Connection getPaymentDbConnection() throws SQLException {
        String url = "jdbc:postgresql://payments-db.shopist.internal:5432/payments" +
                     "?user=payments_svc&password=Str0ngP@ssw0rd2024!&ssl=true";
        return DriverManager.getConnection(url);
    }
}
