// User with admin for testing IAC remediation in CIEM
resource "aws_iam_user" "iac-remediation-user" {
  name = "iac-remediation-user"
  tags = {
    dd_git_file               = "terraform/users.tf"
    dd_git_org                = "DataDog"
    dd_git_repo               = "shopist-infra-iac-demo"
    dd_git_resource_signature = "resource.aws_iam_user.iac-remediation-user"
  }
}

resource "aws_iam_user_policy" "iac-remediation-user" {
  user   = aws_iam_user.iac-remediation-user.id
  name   = "iac-remediation-user"
  policy = file("policies/iac-remediation.json")
}
