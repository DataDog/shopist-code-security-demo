# Shopist S3 buckets
# WARNING: intentionally misconfigured for Datadog IaC Security demo

# VULN 1: Bucket has no public access block — can be made publicly accessible
resource "aws_s3_bucket" "shopist_product_images" {
  bucket = "shopist-product-images-prod"

  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}

# VULN 2: Public-read ACL exposes all product images to the internet
resource "aws_s3_bucket_acl" "shopist_product_images_acl" {
  bucket = aws_s3_bucket.shopist_product_images.id
  acl    = "public-read"
}

# VULN 3: No server-side encryption — order receipts stored in plaintext
resource "aws_s3_bucket" "shopist_order_receipts" {
  bucket = "shopist-order-receipts-prod"

  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}

# No aws_s3_bucket_server_side_encryption_configuration block for shopist_order_receipts

# VULN 4: Versioning disabled — no recovery from accidental deletion of customer data
resource "aws_s3_bucket_versioning" "shopist_order_receipts_versioning" {
  bucket = aws_s3_bucket.shopist_order_receipts.id
  versioning_configuration {
    status = "Disabled"
  }
}

# VULN 5: Access logging disabled on bucket containing payment data
resource "aws_s3_bucket" "shopist_payment_exports" {
  bucket = "shopist-payment-exports-prod"

  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}

# No aws_s3_bucket_logging block for shopist_payment_exports

# VULN 6: Bucket policy grants GetObject to all principals (*)
resource "aws_s3_bucket_policy" "shopist_assets_policy" {
  bucket = aws_s3_bucket.shopist_product_images.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.shopist_product_images.arn}/*"
      }
    ]
  })
}
