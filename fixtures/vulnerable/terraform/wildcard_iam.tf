# expected_rules: NXR-IAC-001
# expected_max_severity: CRITICAL
# description: IAM policy with wildcard Action

resource "aws_iam_role_policy" "bad_policy" {
  name = "bad-policy"
  role = aws_iam_role.example.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
