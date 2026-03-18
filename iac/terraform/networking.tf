# Shopist networking configuration
# WARNING: intentionally misconfigured for Datadog IaC Security demo

# VULN 1: VPC Flow Logs disabled — no network traffic visibility for incident response
resource "aws_vpc" "shopist_main_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  # No aws_flow_log resource associated — VULN 1: Flow Logs not enabled

  tags = {
    Name        = "shopist-main-vpc"
    Project     = "shopist"
    Environment = "production"
  }
}

# VULN 2: Network ACL allows all inbound traffic (0.0.0.0/0 on all ports)
resource "aws_network_acl" "shopist_public_nacl" {
  vpc_id = aws_vpc.shopist_main_vpc.id

  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"  # VULN 2: All inbound traffic allowed on all ports
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name    = "shopist-public-nacl"
    Project = "shopist"
  }
}

# VULN 3: Subnet is configured to assign public IPs automatically
resource "aws_subnet" "shopist_public_subnet" {
  vpc_id                  = aws_vpc.shopist_main_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true  # VULN 3: All instances in subnet get a public IP

  tags = {
    Name    = "shopist-public-subnet"
    Project = "shopist"
  }
}

# VULN 4: CloudTrail not enabled — no audit log of AWS API calls
# (absence of aws_cloudtrail resource for the account)

# VULN 5: Security group with unrestricted egress and broad ingress for database port
resource "aws_security_group" "shopist_db_sg" {
  name        = "shopist-db-sg"
  description = "Security group for Shopist databases"
  vpc_id      = aws_vpc.shopist_main_vpc.id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULN 5: PostgreSQL port open to the internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "shopist-db-sg"
    Project     = "shopist"
    Environment = "production"
  }
}

# VULN 6: ALB access logs disabled — no HTTP request audit trail
resource "aws_lb" "shopist_alb" {
  name               = "shopist-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.shopist_db_sg.id]
  subnets            = [aws_subnet.shopist_public_subnet.id]

  enable_deletion_protection = false  # VULN 6a: ALB can be deleted without protection

  access_logs {
    bucket  = ""
    enabled = false  # VULN 6b: Access logging disabled
  }

  tags = {
    Name        = "shopist-alb"
    Project     = "shopist"
    Environment = "production"
  }
}
