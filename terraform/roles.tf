

resource "aws_iam_role_policy" "iac-remediation" {
  name   = "iac-remediation"
  policy = file("policies/iac-remediation.json")
  role   = aws_iam_role.iac-remediation.name
}
