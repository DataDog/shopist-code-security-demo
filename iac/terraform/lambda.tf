# Shopist Lambda functions
# WARNING: intentionally misconfigured for Datadog IaC Security demo

# VULN 1: Execution role trust policy combined with wildcard permissions grants the function
# far more access than it needs to process checkout events
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

resource "aws_iam_role_policy" "shopist_checkout_lambda_policy" {
  name = "shopist-checkout-lambda-policy"
  role = aws_iam_role.shopist_checkout_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"     # VULN 1: Wildcard action on all resources — should be scoped to specific DynamoDB/SQS actions
        Resource = "*"
      }
    ]
  })
}

# VULN 2: Plaintext secrets (Stripe key, DB password) passed via environment variables instead of
# pulling from Secrets Manager/SSM Parameter Store at runtime
resource "aws_lambda_function" "shopist_checkout_processor" {
  function_name = "shopist-checkout-processor"
  role          = aws_iam_role.shopist_checkout_lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  filename      = "checkout_processor.zip"

  environment {
    variables = {
      STRIPE_SECRET_KEY = "sk_live_DEMO-NOT-A-REAL-KEY-fake-example" # VULN 2: Hardcoded live API key in plaintext env var
      DB_PASSWORD        = "Sh0pist!Prod2024"                            # VULN 2 (cont.): Hardcoded DB password
    }
  }

  # VULN 3: No vpc_config block — function runs outside the VPC with unrestricted outbound
  # internet access instead of being scoped to the private checkout subnet
  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}

# VULN 4: Function URL enabled with NONE auth type — publicly invokable with no authentication
resource "aws_lambda_function_url" "shopist_checkout_processor_url" {
  function_name      = aws_lambda_function.shopist_checkout_processor.function_name
  authorization_type = "NONE" # VULN 4: Anyone on the internet can invoke this function directly

  cors {
    allow_origins = ["*"] # VULN 4 (cont.): Wildcard CORS origin on an unauthenticated endpoint
  }
}

# VULN 5: X-Ray tracing and dead-letter queue both left unconfigured — failed invocations
# (e.g. dropped orders) are silently lost with no observability
resource "aws_lambda_function" "shopist_order_notifier" {
  function_name = "shopist-order-notifier"
  role          = aws_iam_role.shopist_checkout_lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  filename      = "order_notifier.zip"
  # No tracing_config block, no dead_letter_config block

  environment {
    variables = {
      SMTP_PASSWORD = "n0tify-smtp-plaintext-pw" # VULN 5 (cont.): Another plaintext credential in env vars
    }
  }

  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}

# VULN 6: Resource-based policy grants invoke permission to any AWS account (Principal = "*")
resource "aws_lambda_permission" "shopist_order_notifier_public_invoke" {
  statement_id  = "AllowAnyAccountInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.shopist_order_notifier.function_name
  principal     = "*" # VULN 6: Any AWS principal (not scoped to a specific service/account) can invoke this function
}
