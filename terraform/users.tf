

resource "aws_iam_user_policy" "iac-remediation-user" {
  user   = aws_iam_user.iac-remediation-user.id
  name   = "iac-remediation-user"
  policy = file("policies/iac-remediation.json")
}
