provider "aws" {
  region = var.aws_region
  access_key_id = var.aws_access_key_id
  access_secret_key = var.aws_access_secret_key
}

# Variables
variable "aws_region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "app_name" {
  description = "Application name"
  default     = "Player App"
}

variable "aws_access_key_id" {
  description = "AWS ACCESS KEY ID"
  default     = ""
}

variable "aws_access_secret_key" {
  description = "AWS ACCESS SECRET KEY"
  default     = ""
}

# S3 Bucket for Video Uploads
resource "aws_s3_bucket" "video_uploads" {
  bucket = "storage-playerapp"
  
  lifecycle {
    prevent_destroy = true
  }
}

# S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "video_uploads" {
  bucket = aws_s3_bucket.video_uploads.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# S3 Bucket Server-Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "video_uploads" {
  bucket = aws_s3_bucket.video_uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# CloudFront Distribution for Video Content
resource "aws_cloudfront_distribution" "video_cdn" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"

  origin {
    domain_name = aws_s3_bucket.video_uploads.bucket_regional_domain_name
    origin_id   = "playerapp_be"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.video_access.cloudfront_access_identity_path
    }
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "s3-${var.app_name}-videos"

    forwarded_values {
      query_string = false
      headers      = []

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

# CloudFront Origin Access Identity
resource "aws_cloudfront_origin_access_identity" "video_access" {
  comment = "OAI for ${var.app_name} video distribution"
}

# DynamoDB Tables
resource "aws_dynamodb_table" "playerapp_user" {
  name           = "playerapp_user"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  attribute {
    name = "currentClub"
    type = "S"
  }

    attribute {
    name = "email"
    type = "S"
  }

  global_secondary_index {
    name            = "EmailIndex"
    hash_key        = "email"
    projection_type = "ALL"
  }

  tags = {
    Environment = var.environment
    Application = var.app_name
  }
}

resource "aws_dynamodb_table" "feed" {
  name           = "playerapp-feed"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  attribute {
    name = "userId"
    type = "S"
  }

  tags = {
    Environment = var.environment
    Application = var.app_name
  }
}

# ECS Cluster
resource "aws_ecs_cluster" "playerapp_be" {
  name = "${var.app_name}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Environment = var.environment
    Application = var.app_name
  }
}

# ECS Task Definition
resource "aws_ecs_task_definition" "playerapp_be" {
  family                   = "${var.app_name}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512

  container_definitions = jsonencode([
    {
      name  = "playerapp_be"
      image = "779328619870.dkr.ecr.us-east-2.amazonaws.com/playerapp-be:latest"
      
      portMappings = [
        {
          containerPort = 3000
          hostPort      = 3000
        }
      ]

      environment = [
        
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = "/ecs/${var.app_name}-api"
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])

  execution_role_arn = aws_iam_role.ecs_execution_role.arn
  task_role_arn      = aws_iam_role.ecs_task_role.arn
}

# IAM Roles for ECS
resource "aws_iam_role" "ecs_execution_role" {
  name = "${var.app_name}-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role" "ecs_task_role" {
  name = "${var.app_name}-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

# IAM Policy Attachments
resource "aws_iam_role_policy_attachment" "ecs_execution_role_policy" {
  role       = aws_iam_role.ecs_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "dynamodb_access" {
  name = "${var.app_name}-dynamodb-access"
  role = aws_iam_role.ecs_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem"
        ]
        Resource = [
          aws_dynamodb_table.player_profiles.arn,
          aws_dynamodb_table.video_metadata.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "s3_access" {
  name = "${var.app_name}-s3-access"
  role = aws_iam_role.ecs_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:DeleteObject"
        ]
        Resource = [
          aws_s3_bucket.video_uploads.arn,
          "${aws_s3_bucket.video_uploads.arn}/*"
        ]
      }
    ]
  })
}