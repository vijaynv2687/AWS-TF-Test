// Please observe the places with these symbols <>, in there, you need to provide relavent IDs, names for your learning.
 
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "5.44.0"
    }
  }
}

provider "aws" {
  region = "ap-south-1"
  access_key = "<paste access key>"
  secret_key = "<paste secret key>"
}

resource "aws_instance" "Webapp" {
  ami                                  = "<paste ami id>"
  associate_public_ip_address          = true
  availability_zone                    = "ap-south-1a"
  disable_api_stop                     = false
  disable_api_termination              = false
  ebs_optimized                        = false
  get_password_data                    = false
  hibernation                          = false
  host_id                              = null
  host_resource_group_arn              = null
  iam_instance_profile                 = null
  instance_initiated_shutdown_behavior = "stop"
  instance_type                        = "t2.micro"
  key_name                             = "<paste aws pem key file name>"
  monitoring                           = false
  placement_group                      = null
  placement_partition_number           = 0
  secondary_private_ips                = []
  source_dest_check                    = true
  subnet_id                            = "<paste subnet id>"
  tags = {
    Name = "Webapp"
  }
  tags_all = {
    Name = "Webapp"
  }
  tenancy                     = "default"
  user_data                   = null
  user_data_base64            = null
  user_data_replace_on_change = null
  volume_tags                 = null
  capacity_reservation_specification {
    capacity_reservation_preference = "open"
  }
 
  credit_specification {
    cpu_credits = "standard"
  }
  enclave_options {
    enabled = false
  }
  maintenance_options {
    auto_recovery = "default"
  }
  metadata_options {
    http_endpoint               = "enabled"
    http_protocol_ipv6          = "disabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "optional"
    instance_metadata_tags      = "disabled"
  }
  private_dns_name_options {
    enable_resource_name_dns_a_record    = true
    enable_resource_name_dns_aaaa_record = false
    hostname_type                        = "ip-name"
  }
  root_block_device {
    delete_on_termination = true
    encrypted             = false
    iops                  = 3000
    kms_key_id            = null
    tags                  = {}
    tags_all              = {}
    throughput            = 125
    volume_size           = 10
    volume_type           = "gp3"
  }
}
resource "aws_s3_bucket" "<privatecaname>" {
  bucket        = "<privatecaname>"
  force_destroy = true
}

data "aws_iam_policy_document" "acmpca_bucket_access" {
  statement {
    actions = [
      "s3:GetBucketAcl",
      "s3:GetBucketLocation",
      "s3:PutObject",
      "s3:PutObjectAcl",
    ]

    resources = [
      aws_s3_bucket.<privatecaname>.arn,
      "${aws_s3_bucket.<privatecaname>.arn}/*",
    ]

    principals {
      identifiers = ["acm-pca.amazonaws.com"]
      type        = "Service"
    }
  }
}

resource "aws_s3_bucket_policy" "<privatecaname>" {
  bucket = aws_s3_bucket.<privatecaname>.id
  policy = data.aws_iam_policy_document.acmpca_bucket_access.json
}

resource "aws_acmpca_certificate_authority" "<privatecaname>" {
  certificate_authority_configuration {
    key_algorithm     = "RSA_4096"
    signing_algorithm = "SHA512WITHRSA"

    subject {
      common_name = "<DreamCompany.com>"
    }
  }

  revocation_configuration {
    crl_configuration {
      custom_cname       = "crl.<DreamCompany>.com"
      enabled            = true
      expiration_in_days = 7
      s3_bucket_name     = aws_s3_bucket.<privatecaname>.id
      s3_object_acl      = "BUCKET_OWNER_FULL_CONTROL"
    }
  }

  depends_on = [aws_s3_bucket_policy.<privatecaname>]
}

resource "aws_vpc" "webappvpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_security_group" "webapplbsg" {
  name        = "allow_tls_webapp"
  description = "Allow TLS inbound traffic and all outbound traffic"
  vpc_id      = "<paste vpc id>"

  tags = {
    Name = "allow_tls"
  }
}
//below is fine
resource "aws_vpc_security_group_ingress_rule" "allow_tls_ipv4" {
  security_group_id = aws_security_group.webapplbsg.id
  cidr_ipv4         = aws_vpc.webappvpc.cidr_block
  from_port         = 443
  ip_protocol       = "tcp"
  to_port           = 443
}

resource "aws_lb_target_group" "webapptg" {
  name     = "webapptg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = "<paste VPC ID>"
}

resource "aws_lb_target_group_attachment" "newwebapplb" {
  target_group_arn = aws_lb_target_group.webapptg.arn
  target_id        = aws_instance.Webapp.id
  port             = 80
}

resource "aws_lb" "newwebapplb" {
  name               = "webapplb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.webapplbsg.id]
  subnets            = ["<paste subnet ID>, <paste subnet ID>,<paste subnet ID>"]

  enable_deletion_protection = false

  tags = {
    Environment = "production"
  }
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = aws_lb.newwebapplb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "<paste arn of acm cert - arn:aws:acm:ap-south-1:091777882795:certificate/f83442f>"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.webapptg.arn
  }
}

resource "aws_acm_certificate" "cert" {
  domain_name       = "<paste domain url>"
  validation_method = "DNS"

  tags = {
    Environment = "test"
  }

  lifecycle {
    create_before_destroy = true
  }
}
