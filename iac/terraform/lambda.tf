# Shopist Lambda functions

resource "aws_iam_role" "shopist_checkout_lambda_role" {
  name = "shopist-checkout-lambda-role"

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

  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}

# VULN 1: Wildcard action on all resources — should be scoped to specific DynamoDB/SQS actions
resource "aws_iam_role_policy" "shopist_checkout_lambda_policy" {
  name = "shopist-checkout-lambda-policy"
  role = aws_iam_role.shopist_checkout_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "shopist_checkout_processor" {
  function_name = "shopist-checkout-processor"
  role          = aws_iam_role.shopist_checkout_lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  filename      = "checkout_processor.zip"

  environment {
    variables = {
      # VULN 2: Plaintext secrets passed via environment variables instead of pulling from
      # Secrets Manager/SSM Parameter Store at runtime
      STRIPE_SECRET_KEY = "sk_live_DEMO-NOT-A-REAL-KEY-fake-example"
      DB_PASSWORD        = "Sh0pist!Prod2024"
    }
  }

  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}

# VULN 3: Function URL enabled with NONE auth type and wildcard CORS — publicly invokable
# with no authentication from any origin
resource "aws_lambda_function_url" "shopist_checkout_processor_url" {
  function_name      = aws_lambda_function.shopist_checkout_processor.function_name
  authorization_type = "NONE"

  cors {
    allow_origins = ["*"]
  }
}
