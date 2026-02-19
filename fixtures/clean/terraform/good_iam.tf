# expected_rules: []
# expected_max_severity: none
# description: IAM policy with explicit minimal permissions and scoped resources

resource "aws_iam_role_policy" "good_policy" {
  name = "good-policy"
  role = aws_iam_role.example.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "arn:aws:s3:::my-bucket/*"
      }
    ]
  })
}
