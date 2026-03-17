# Shopist RDS databases
# WARNING: intentionally misconfigured for Datadog IaC Security demo

# VULN 1: RDS instance is publicly accessible — database exposed to the internet
resource "aws_db_instance" "shopist_orders_db" {
  identifier          = "shopist-orders-db-prod"
  engine              = "postgres"
  engine_version      = "13.7"
  instance_class      = "db.t3.medium"
  allocated_storage   = 50
  db_name             = "shopist_orders"
  username            = "shopist_admin"
  password            = "Sh0pist@dmin123"  # VULN 2: Hardcoded password in plain text
  publicly_accessible = true               # VULN 1: Database accessible from the internet

  skip_final_snapshot = true

  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}

# VULN 3: Encryption at rest disabled — customer PII stored in plaintext
resource "aws_db_instance" "shopist_customers_db" {
  identifier        = "shopist-customers-db-prod"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.medium"
  allocated_storage = 100
  db_name           = "shopist_customers"
  username          = "shopist_admin"
  password          = "Sup3rS3cr3t!"
  storage_encrypted = false  # VULN 3: No encryption for customer PII database

  # VULN 4: No backup retention — data loss risk
  backup_retention_period = 0

  # VULN 5: No deletion protection — database can be deleted accidentally
  deletion_protection = false

  skip_final_snapshot = true

  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}

# VULN 6: No Multi-AZ — single point of failure for payment database
resource "aws_db_instance" "shopist_payments_db" {
  identifier        = "shopist-payments-db-prod"
  engine            = "postgres"
  engine_version    = "14.3"
  instance_class    = "db.t3.large"
  allocated_storage = 200
  db_name           = "shopist_payments"
  username          = "shopist_payments_admin"
  password          = "P@yments2024!"
  multi_az          = false  # VULN 6: No high availability for payments database

  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}
