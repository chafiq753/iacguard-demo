# Infrastructure de démo VOLONTAIREMENT vulnérable, pour tester iac-guard.
# Chaque ressource ci-dessous doit déclencher au moins un finding Checkov.

provider "aws" {
  region = "us-east-1"

  # Secret volontairement en clair : Gitleaks doit le détecter.
  # (Clé d'exemple officielle AWS, elle n'ouvre rien.)
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# S3 public en lecture -> CKV_AWS_20
resource "aws_s3_bucket" "assets" {
  bucket = "iacguard-demo-assets"
  acl    = "public-read"
}

# SSH ouvert au monde entier -> CKV_AWS_24
resource "aws_security_group" "bastion" {
  name = "bastion-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Volume non chiffré -> CKV_AWS_3
resource "aws_ebs_volume" "cache" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
}

# Base de données non chiffrée -> CKV_AWS_16
resource "aws_db_instance" "analytics" {
  identifier        = "analytics"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "admin"
  password          = "SuperSecret123!" # secret en dur -> finding aussi
  storage_encrypted = false
}
