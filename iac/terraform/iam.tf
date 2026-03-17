# Shopist IAM roles and policies
# WARNING: intentionally misconfigured for Datadog IaC Security demo

# VULN 1: IAM policy grants wildcard (*) actions on all resources — full admin access
resource "aws_iam_policy" "shopist_app_policy" {
  name        = "shopist-app-policy"
  description = "Policy for Shopist application servers"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowAll"
        Effect   = "Allow"
        Action   = "*"        # VULN 1: Wildcard action — grants full AWS access
        Resource = "*"
      }
    ]
  })
}

# VULN 2: IAM role trust policy allows any AWS principal to assume it
resource "aws_iam_role" "shopist_api_role" {
  name = "shopist-api-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "*" }  # VULN 2: Any AWS account can assume this role
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "shopist_api_admin" {
  role       = aws_iam_role.shopist_api_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"  # VULN 3: Admin policy attached
}

# VULN 4: IAM user with programmatic access and admin policy (no MFA enforced)
resource "aws_iam_user" "shopist_deploy_user" {
  name = "shopist-deploy-user"

  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}

resource "aws_iam_user_policy_attachment" "shopist_deploy_admin" {
  user       = aws_iam_user.shopist_deploy_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"  # VULN 4: User has admin access
}

# VULN 5: Inline policy allows s3:* on all buckets — over-privileged Lambda
resource "aws_iam_role" "shopist_lambda_role" {
  name = "shopist-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "shopist_lambda_s3_policy" {
  name = "shopist-lambda-s3-policy"
  role = aws_iam_role.shopist_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:*"    # VULN 5: Wildcard S3 action — should be limited to specific operations
        Resource = "*"
      }
    ]
  })
}

# VULN 6: Password policy does not enforce minimum length or complexity
resource "aws_iam_account_password_policy" "shopist_password_policy" {
  minimum_password_length        = 6      # VULN 6: Minimum 6 chars is too short (should be 14+)
  require_lowercase_characters   = false
  require_numbers                = false
  require_uppercase_characters   = false
  require_symbols                = false
  allow_users_to_change_password = true
}
