// Role with admin for testing IAC remediation in CIEM
resource "aws_iam_role" "iac-remediation" {
  name               = "iac-remediation"
  assume_role_policy = file("policies/assume/iac-remediation.json")
  tags = {
    dd_git_file               = "terraform/roles.tf"
    dd_git_org                = "DataDog"
    dd_git_repo               = "shopist-infra-iac-demo"
    dd_git_resource_signature = "resource.aws_iam_role.iac-remediation"
  }
}

resource "aws_iam_role_policy" "iac-remediation" {
  name   = "iac-remediation"
  policy = file("policies/iac-remediation.json")
  role   = aws_iam_role.iac-remediation.name
}
