import Stripe from 'stripe';
import { S3Client } from '@aws-sdk/client-s3';
import { Pool } from 'pg';

// VULN 1: Hardcoded Stripe secret key in source code
const stripe = new Stripe('sk_live_51HqT3rKZ2eM8xJv0nPqW9cYd3fGhR7mKLtA2bVwXnZpQeS6uDcFjIyOl4gMs', {
    apiVersion: '2023-10-16',
});

export async function chargeCustomer(customerId: string, amount: number): Promise<Stripe.PaymentIntent> {
    const paymentIntent = await stripe.paymentIntents.create({
        amount,
        currency: 'usd',
        customer: customerId,
        description: 'Shopist order payment',
    });
    return paymentIntent;
}

// VULN 2: Hardcoded AWS credentials in S3Client constructor
const s3Client = new S3Client({
    region: 'us-east-1',
    credentials: {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE3',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY3',
    },
});

export async function uploadInvoice(orderId: string, invoiceBuffer: Buffer): Promise<string> {
    const key = `invoices/${orderId}.pdf`;
    await s3Client.send({
        Bucket: 'shopist-invoices-prod',
        Key: key,
        Body: invoiceBuffer,
    } as any);
    return `https://shopist-invoices-prod.s3.amazonaws.com/${key}`;
}

// VULN 3: Hardcoded DB password in connection string
const pool = new Pool({
    connectionString: 'postgresql://shopist_admin:Sup3rS3cr3tProdP@ssw0rd!@prod-db.shopist.internal:5432/shopist_payments',
});

export async function getPaymentHistory(userId: number): Promise<any[]> {
    const result = await pool.query(
        'SELECT * FROM payment_transactions WHERE user_id = $1 ORDER BY created_at DESC',
        [userId]
    );
    return result.rows;
}
