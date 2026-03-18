# Shopist EC2 instances and security groups
# WARNING: intentionally misconfigured for Datadog IaC Security demo

# VULN 1: Security group allows SSH (port 22) from any IP address
resource "aws_security_group" "shopist_app_sg" {
  name        = "shopist-app-sg"
  description = "Security group for Shopist application servers"
  vpc_id      = aws_vpc.shopist_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULN 1: SSH open to the entire internet
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}

# VULN 2: Security group allows RDP (port 3389) from any IP address
resource "aws_security_group" "shopist_admin_sg" {
  name        = "shopist-admin-sg"
  description = "Security group for Shopist admin bastion"
  vpc_id      = aws_vpc.shopist_vpc.id

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULN 2: RDP open to the entire internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Project     = "shopist"
    Environment = "production"
  }
}

# VULN 3: EC2 instance does not enforce IMDSv2 — vulnerable to SSRF-based metadata theft
resource "aws_instance" "shopist_api_server" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t3.medium"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"  # VULN 3: IMDSv2 not required (should be "required")
    http_put_response_hop_limit = 2           # hop limit > 1 allows container escape to metadata
  }

  root_block_device {
    volume_size           = 20
    encrypted             = false  # VULN 4: Root volume not encrypted
    delete_on_termination = true
  }

  vpc_security_group_ids = [aws_security_group.shopist_app_sg.id]

  tags = {
    Name        = "shopist-api-server"
    Project     = "shopist"
    Environment = "production"
  }
}

# VULN 5: EBS volume not encrypted — contains customer order data
resource "aws_ebs_volume" "shopist_data_volume" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false  # VULN 5: Unencrypted EBS volume with sensitive data

  tags = {
    Name    = "shopist-data-volume"
    Project = "shopist"
  }
}

resource "aws_vpc" "shopist_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name    = "shopist-vpc"
    Project = "shopist"
  }
}
