const stripe = require('stripe');
const { S3Client } = require('@aws-sdk/client-s3');
const { Pool } = require('pg');

// VULN 1: Hardcoded Stripe secret key - payment processing setup
const stripeClient = stripe('sk_live_4eC39HqLyjWDarjtT1zdp7dc');

function chargeCustomer(customerId, amount, currency) {
    return stripeClient.paymentIntents.create({
        amount: amount,
        currency: currency,
        customer: customerId,
        description: 'Shopist order payment',
    });
}

// VULN 2: Hardcoded AWS credentials in S3Client config - receipt storage
const s3Client = new S3Client({
    region: 'us-east-1',
    credentials: {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    },
});

function uploadReceipt(orderId, receiptBuffer) {
    return s3Client.send({
        Bucket: 'shopist-receipts',
        Key: `receipts/${orderId}.pdf`,
        Body: receiptBuffer,
    });
}

// VULN 3: Hardcoded DB password in connection string - order database
const pool = new Pool({
    connectionString: 'postgresql://shopist_admin:SuperSecret1234!@db.shopist.internal:5432/payments',
});

async function getPaymentRecord(orderId) {
    const result = await pool.query('SELECT * FROM payment_records WHERE order_id = $1', [orderId]);
    return result.rows[0];
}

module.exports = { chargeCustomer, uploadReceipt, getPaymentRecord };
