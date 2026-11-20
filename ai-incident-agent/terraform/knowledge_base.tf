resource "aws_s3_bucket" "runbooks" {
  bucket        = "${var.project_name}-${var.environment}-runbooks-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
  tags          = local.common_tags
}

resource "aws_s3_bucket_public_access_block" "runbooks" {
  bucket                  = aws_s3_bucket.runbooks.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "runbooks" {
  bucket = aws_s3_bucket.runbooks.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_object" "runbooks" {
  for_each = fileset("${path.module}/../knowledge-base/runbooks", "**")
  bucket   = aws_s3_bucket.runbooks.id
  key      = "runbooks/${each.value}"
  source   = "${path.module}/../knowledge-base/runbooks/${each.value}"
  etag     = filemd5("${path.module}/../knowledge-base/runbooks/${each.value}")
  content_type = endswith(each.value, ".md") ? "text/markdown" : "application/octet-stream"
}

resource "aws_s3vectors_vector_bucket" "runbooks" {
  vector_bucket_name = "${var.project_name}-${var.environment}-runbook-vectors"
}

resource "aws_s3vectors_index" "runbooks" {
  index_name         = "incident-runbooks-index"
  vector_bucket_name = aws_s3vectors_vector_bucket.runbooks.vector_bucket_name
  data_type          = "float32"
  dimension          = 1024
  distance_metric    = "cosine"
}

data "aws_iam_policy_document" "bedrock_kb_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrock.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:bedrock:${var.aws_region}:${data.aws_caller_identity.current.account_id}:knowledge-base/*"]
    }
  }
}

resource "aws_iam_role" "bedrock_kb" {
  name               = "${var.project_name}-knowledge-base-role"
  assume_role_policy = data.aws_iam_policy_document.bedrock_kb_trust.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy" "bedrock_kb" {
  name = "${var.project_name}-knowledge-base-access"
  role = aws_iam_role.bedrock_kb.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadRunbookSource"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = [aws_s3_bucket.runbooks.arn]
      },
      {
        Sid      = "ReadRunbookObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["${aws_s3_bucket.runbooks.arn}/*"]
      },
      {
        Sid    = "UseEmbeddingModel"
        Effect = "Allow"
        Action = ["bedrock:InvokeModel"]
        Resource = [
          "arn:${data.aws_partition.current.partition}:bedrock:${var.aws_region}::foundation-model/amazon.titan-embed-text-v2:0"
        ]
      },
      {
        Sid    = "ManageKnowledgeBaseVectors"
        Effect = "Allow"
        Action = [
          "s3vectors:GetVectors",
          "s3vectors:PutVectors",
          "s3vectors:DeleteVectors",
          "s3vectors:QueryVectors"
        ]
        Resource = [
          aws_s3vectors_vector_bucket.runbooks.arn,
          aws_s3vectors_index.runbooks.index_arn
        ]
      }
    ]
  })
}

resource "aws_bedrockagent_knowledge_base" "runbooks" {
  name        = "${var.project_name}-${var.environment}-runbooks"
  description = "Reviewed operational runbooks for the AWS incident triage agent"
  role_arn    = aws_iam_role.bedrock_kb.arn

  knowledge_base_configuration {
    type = "VECTOR"
    vector_knowledge_base_configuration {
      embedding_model_arn = "arn:${data.aws_partition.current.partition}:bedrock:${var.aws_region}::foundation-model/amazon.titan-embed-text-v2:0"
      embedding_model_configuration {
        bedrock_embedding_model_configuration {
          dimensions          = 1024
          embedding_data_type = "FLOAT32"
        }
      }
    }
  }

  storage_configuration {
    type = "S3_VECTORS"
    s3_vectors_configuration {
      index_arn = aws_s3vectors_index.runbooks.index_arn
    }
  }

  depends_on = [aws_iam_role_policy.bedrock_kb]
  tags       = local.common_tags
}

resource "aws_bedrockagent_data_source" "runbooks" {
  knowledge_base_id = aws_bedrockagent_knowledge_base.runbooks.id
  name              = "${var.project_name}-runbooks-source"
  description       = "Version-controlled reviewed incident runbooks"

  data_source_configuration {
    type = "S3"
    s3_configuration {
      bucket_arn       = aws_s3_bucket.runbooks.arn
      inclusion_prefixes = ["runbooks/"]
    }
  }

  vector_ingestion_configuration {
    chunking_configuration {
      chunking_strategy = "FIXED_SIZE"
      fixed_size_chunking_configuration {
        max_tokens         = 512
        overlap_percentage = 20
      }
    }
  }

  depends_on = [
    aws_s3_object.runbooks,
    aws_bedrockagent_knowledge_base.runbooks
  ]
}

output "bedrock_knowledge_base_id" {
  description = "Bedrock Knowledge Base ID used by the incident agent"
  value       = aws_bedrockagent_knowledge_base.runbooks.id
}

output "runbook_source_bucket" {
  description = "S3 bucket containing version-controlled runbooks"
  value       = aws_s3_bucket.runbooks.bucket
}

output "runbook_data_source_id" {
  description = "Bedrock Knowledge Base S3 data source ID"
  value       = aws_bedrockagent_data_source.runbooks.data_source_id
}
