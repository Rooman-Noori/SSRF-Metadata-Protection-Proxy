terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

resource "aws_s3_bucket" "intentionally_public_demo" {
  bucket = "metaguard-prowler-iac-demo"
}

resource "aws_s3_bucket_public_access_block" "intentionally_public_demo" {
  bucket                  = aws_s3_bucket.intentionally_public_demo.id
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_security_group" "intentionally_open_ssh_demo" {
  name = "metaguard-prowler-open-ssh-demo"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
