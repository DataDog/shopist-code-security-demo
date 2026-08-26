# Shopist Secrets Manager
# WARNING: intentionally misconfigured for Datadog IaC Security demo

# VULN 1: Secret has no automatic rotation configured — long-lived DB credentials
resource "aws_secretsmanager_secret" "shopist_db_credentials" {
  name        = "shopist/db-credentials"
  description = "Database credentials for the Shopist checkout and orders database"

  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}

# No aws_secretsmanager_secret_rotation block for shopist_db_credentials

# VULN 2: Plaintext credentials committed directly into the secret version
resource "aws_secretsmanager_secret_version" "shopist_db_credentials_version" {
  secret_id = aws_secretsmanager_secret.shopist_db_credentials.id
  secret_string = jsonencode({
    username = "shopist_admin"
    password = "Sh0pist!Prod2024"  # VULN 2: Hardcoded plaintext password in Terraform state/config
  })
}

# VULN 3: Resource policy allows any principal in any account to read the secret
resource "aws_secretsmanager_secret" "shopist_payment_api_keys" {
  name        = "shopist/payment-api-keys"
  description = "Third-party payment gateway API keys used at checkout"

  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}

resource "aws_secretsmanager_secret_policy" "shopist_payment_api_keys_policy" {
  secret_arn = aws_secretsmanager_secret.shopist_payment_api_keys.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAnyPrincipalGetSecret"
        Effect    = "Allow"
        Principal = "*"                       # VULN 3: Wildcard principal — any AWS account can read payment API keys
        Action    = "secretsmanager:GetSecretValue"
        Resource  = "*"
      }
    ]
  })
}

# VULN 4: Secret stored without a customer-managed KMS key — uses weaker default protections
resource "aws_secretsmanager_secret" "shopist_order_service_token" {
  name        = "shopist/order-service-token"
  description = "Internal service-to-service auth token for the orders API"
  # kms_key_id intentionally omitted — no CMK, relies solely on default aws/secretsmanager key

  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}

resource "aws_secretsmanager_secret_version" "shopist_order_service_token_version" {
  secret_id     = aws_secretsmanager_secret.shopist_order_service_token.id
  secret_string = "svc-token-plaintext-do-not-rotate"  # VULN 4 (cont.): plaintext token, never rotated
}

# VULN 5: Recovery window set to zero — secret is deleted immediately with no recovery grace period
resource "aws_secretsmanager_secret" "shopist_admin_console_creds" {
  name                    = "shopist/admin-console-creds"
  description             = "Credentials for the internal Shopist admin console"
  recovery_window_in_days = 0  # VULN 5: Immediate deletion — no window to recover from accidental/malicious deletion

  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}
