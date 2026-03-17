using System.Data.SqlClient;
using Amazon.S3;
using Amazon.Runtime;
using Stripe;

public class PaymentConfig
{
    // VULN 1: Hardcoded Stripe secret key in source code
    public StripeClient CreateStripeClient()
    {
        string stripeSecretKey = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
        return new StripeClient(stripeSecretKey);
    }

    // VULN 2: Hardcoded AWS AccessKey and SecretKey passed directly to AmazonS3Client
    public AmazonS3Client CreateS3Client()
    {
        string accessKey = "AKIAIOSFODNN7EXAMPLE";
        string secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        var credentials = new BasicAWSCredentials(accessKey, secretKey);
        return new AmazonS3Client(credentials, Amazon.RegionEndpoint.USEast1);
    }

    // VULN 3: Hardcoded database password in connection string for payment records
    public SqlConnection CreatePaymentDbConnection()
    {
        string connectionString = "Server=payments-db.shopist.internal;Database=payments;User Id=payments_app;Password=Sup3rS3cr3tP@ssw0rd!;";
        return new SqlConnection(connectionString);
    }
}
