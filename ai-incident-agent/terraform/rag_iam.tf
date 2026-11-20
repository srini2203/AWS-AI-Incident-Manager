resource "aws_iam_role_policy" "incident_rag_retrieval" {
  name = "${var.project_name}-rag-retrieval"
  role = aws_iam_role.incident.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "RetrieveIncidentRunbooks"
      Effect   = "Allow"
      Action   = ["bedrock:Retrieve"]
      Resource = [aws_bedrockagent_knowledge_base.runbooks.arn]
    }]
  })
}
