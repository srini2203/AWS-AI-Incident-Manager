resource "aws_bedrock_guardrail" "incident" {
  count = var.enable_bedrock_guardrails ? 1 : 0

  name                      = "${var.project_name}-guardrail"
  description               = "Security guardrail for AWS incident triage analysis"
  blocked_input_messaging   = "The incident evidence contains content that violates security policy."
  blocked_outputs_messaging = "The generated analysis was blocked by the security policy."

  content_policy_config {
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "HIGH"
      output_strength = "NONE"
      input_action    = "BLOCK"
      output_action   = "NONE"
      input_enabled   = true
      output_enabled  = false
    }
  }

  sensitive_information_policy_config {
    pii_entities_config {
      type          = "EMAIL"
      action        = "ANONYMIZE"
      input_action  = "ANONYMIZE"
      output_action = "ANONYMIZE"
      input_enabled = true
      output_enabled = true
    }

    pii_entities_config {
      type          = "PHONE"
      action        = "ANONYMIZE"
      input_action  = "ANONYMIZE"
      output_action = "ANONYMIZE"
      input_enabled = true
      output_enabled = true
    }

    pii_entities_config {
      type          = "ADDRESS"
      action        = "ANONYMIZE"
      input_action  = "ANONYMIZE"
      output_action = "ANONYMIZE"
      input_enabled = true
      output_enabled = true
    }

    regexes_config {
      name          = "aws_access_key"
      description   = "Detect AWS access key identifiers"
      pattern       = "(AKIA|ASIA)[A-Z0-9]{16}"
      action        = "BLOCK"
      input_action  = "BLOCK"
      output_action = "BLOCK"
      input_enabled = true
      output_enabled = true
    }
  }

  tags = local.common_tags
}

resource "aws_bedrock_guardrail_version" "incident" {
  count = var.enable_bedrock_guardrails ? 1 : 0

  guardrail_arn = aws_bedrock_guardrail.incident[0].guardrail_arn
  description   = "Production incident triage guardrail version"
}