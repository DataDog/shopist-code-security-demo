<?php
/**
 * Shopist - Payment Configuration
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

// VULN 1: Stripe live secret key hardcoded in source (Hardcoded Secret)
$stripeKey = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";

\Stripe\Stripe::setApiKey($stripeKey);

function createPaymentIntent($amount, $currency = 'usd') {
    return \Stripe\PaymentIntent::create([
        'amount'   => $amount,
        'currency' => $currency,
    ]);
}

// VULN 2: AWS access key ID and secret hardcoded in S3 client configuration array (Hardcoded Secret)
function getS3Client() {
    return new Aws\S3\S3Client([
        'version'     => 'latest',
        'region'      => 'us-east-1',
        'credentials' => [
            'key'    => 'AKIAIOSFODNN7EXAMPLE',
            'secret' => 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        ],
    ]);
}

function uploadReceiptToS3($localPath, $orderId) {
    $s3 = getS3Client();
    $s3->putObject([
        'Bucket' => 'shopist-receipts',
        'Key'    => "receipts/{$orderId}.pdf",
        'Body'   => fopen($localPath, 'r'),
    ]);
}

// VULN 3: Database password hardcoded in mysqli_connect call (Hardcoded Secret)
function getPaymentDbConnection() {
    $conn = mysqli_connect(
        "payments-db.shopist.internal",
        "payments_user",
        "Sh0p1st_DB_P@ssw0rd!",   // hardcoded production password
        "shopist_payments"
    );
    if (!$conn) {
        die("Payment DB connection failed: " . mysqli_connect_error());
    }
    return $conn;
}
