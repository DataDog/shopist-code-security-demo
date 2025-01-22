// Unattached admin policy for testing IAC remediation in CIEM
resource "aws_iam_policy" "iac-remediation-policy" {
  name   = "iac-remediation-policy"
  policy = file("policies/iac-remediation.json")
  tags = {
    dd_git_file               = "terraform/policies.tf"
    dd_git_org                = "DataDog"
    dd_git_repo               = "shopist-code-security-demo"
    dd_git_resource_signature = "resource.aws_iam_role.iac-remediation-policy"
  }
}
