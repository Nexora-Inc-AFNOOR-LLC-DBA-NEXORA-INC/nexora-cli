# expected_rules: NXR-IAC-002
# expected_max_severity: CRITICAL
# description: Hardcoded AWS credentials in Terraform

provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
