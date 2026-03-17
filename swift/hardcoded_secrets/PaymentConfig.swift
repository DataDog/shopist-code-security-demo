// PaymentConfig.swift
// Shopist – Payment gateway configuration
// ⚠️  DEMO FILE – Intentionally vulnerable for Datadog Code Security demo
// DO NOT USE IN PRODUCTION

import Foundation

// VULN 1: Hardcoded Stripe secret key
// Live Stripe secret keys must never be committed to source control; any process
// or log that accesses this constant will expose the key.
struct StripeConfig {
    static let stripeKey = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
    static let stripePublishableKey = "pk_live_TYooMQauvdEDq54NiTphI7jx"
    static let webhookSecret = "whsec_4eC39HqLyjWDarjtT1zdp7dc1234567890"

    static var defaultHeaders: [String: String] {
        return [
            "Authorization": "Bearer \(stripeKey)",
            "Content-Type": "application/x-www-form-urlencoded"
        ]
    }
}

// VULN 2: Hardcoded AWS access key and secret key in a credentials struct
// These credentials grant programmatic access to AWS services (S3, SES, etc.).
// Committing them allows anyone with repo access to enumerate and exfiltrate data.
struct AWSCredentials {
    static let accessKeyId     = "AKIAIOSFODNN7EXAMPLE"
    static let secretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    static let region          = "us-east-1"
    static let s3BucketName    = "shopist-product-images"
    static let sesRegion        = "us-east-1"
}

// VULN 3: Hardcoded database password embedded in a connection URL string
// The full connection string (including password) is embedded in source; rotating
// the credential requires a code change and new deployment.
struct DatabaseConfig {
    static let host            = "shopist-prod-db.cluster-ro-abc123.us-east-1.rds.amazonaws.com"
    static let port            = 5432
    static let databaseName    = "shopist_production"
    static let username        = "shopist_admin"
    static let password        = "Sup3rS3cretProdPassw0rd!"
    static let connectionURL   = "postgresql://shopist_admin:Sup3rS3cretProdPassw0rd!@shopist-prod-db.cluster-ro-abc123.us-east-1.rds.amazonaws.com:5432/shopist_production"

    static func buildConnectionString() -> String {
        return "postgresql://\(username):\(password)@\(host):\(port)/\(databaseName)"
    }
}
