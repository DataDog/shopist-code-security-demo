resource "aws_s3_bucket" "remediation_demo_bucket" {
  bucket = "iac-remediation-bucket"

  tags = {
    "dd_git_file"           = "terraform/main.tf"
    "dd_git_org"            = "DataDog"
    "dd_git_repo"           = "github.com/DataDog/shopist-infra-iac-demo"
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

data "aws_availability_zones" "available_iac" {
  state = "available"
}

resource "aws_ebs_volume" "iac_volume" {
  availability_zone = data.aws_availability_zones.available_iac.names[0]
  size              = 1

  tags = {
    Name = "iac-scanning"
    Team = "demo"
  }
}
