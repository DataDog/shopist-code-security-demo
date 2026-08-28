# Shopist Secrets Manager

# VULN 1: Resource policy allows any principal in any account to read the secret
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
        Principal = "*"                       # VULN 1: Wildcard principal — any AWS account can read payment API keys
        Action    = "secretsmanager:GetSecretValue"
        Resource  = "*"
      }
    ]
  })
}

# VULN 2: Plaintext credentials committed directly into the secret version
resource "aws_secretsmanager_secret" "shopist_db_credentials" {
  name        = "shopist/db-credentials"
  description = "Database credentials for the Shopist checkout and orders database"

  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}

resource "aws_secretsmanager_secret_version" "shopist_db_credentials_version" {
  secret_id = aws_secretsmanager_secret.shopist_db_credentials.id
  secret_string = jsonencode({
    username = "shopist_admin"
    password = "Sh0pist!Prod2024"  # VULN 2: Hardcoded plaintext password in Terraform state/config
  })
}
