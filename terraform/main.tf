resource "aws_s3_bucket" "remediation_demo_bucket" {
  bucket = "iac-remediation-bucket"

  tags = {
    "dd_git_file"           = "terraform/main.tf"
    "dd_git_org"            = "DataDog"
    "dd_git_repo"           = "github.com/DataDog/shopist-code-security-demo"
    "dd_git_resource_lines" = "1:9"
  }
}

resource "aws_s3_bucket_acl" "remediation_demo_bucket" {
  bucket = aws_s3_bucket.remediation_demo_bucket.id
  acl    = "private"
}

resource "aws_s3_bucket_versioning" "versioning_remediation_demo_bucket" {
  bucket = aws_s3_bucket.remediation_demo_bucket.id
  versioning_configuration {
    status = "Disabled"
  }
}

resource "google_sql_database_instance" "sql_database_instance" {
  name             = var.name
  database_version = var.database_version
  region           = var.region
  settings {
    tier = var.tier

    dynamic "backup_configuration" {
      for_each = var.backup_enabled != null || var.backup_start_time != null ? [1] : []
      content {
        enabled    = var.backup_enabled
        start_time = var.backup_start_time
      }
    }

    user_labels = var.user_labels
  }
}

resource "google_storage_bucket" "bucket" {
  name     = var.cloud_storage_bucket_name
  location = var.region
  project  = var.project_name
}