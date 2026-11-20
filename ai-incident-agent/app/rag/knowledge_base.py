from __future__ import annotations

import os
from typing import Any

import boto3

from app.config import AWS_REGION
from app.security.redaction import redact_payload


def retrieve_runbook_context(
    query: str,
    knowledge_base_id: str | None = None,
    client: Any | None = None,
) -> list[dict[str, Any]]:
    kb_id = knowledge_base_id or os.getenv("BEDROCK_KNOWLEDGE_BASE_ID", "")
    if not kb_id:
        raise ValueError("BEDROCK_KNOWLEDGE_BASE_ID is required")

    if not query.strip():
        raise ValueError("query cannot be empty")

    runtime = client or boto3.client(
        "bedrock-agent-runtime",
        region_name=AWS_REGION,
    )
    response = runtime.retrieve(
        knowledgeBaseId=kb_id,
        retrievalQuery={"text": query.strip()},
        retrievalConfiguration={
            "vectorSearchConfiguration": {
                "numberOfResults": 5,
            }
        },
    )

    results = []
    for item in response.get("retrievalResults", []):
        content = item.get("content", {}).get("text", "")
        location = item.get("location", {}).get("s3Location", {}).get("uri", "")
        if content:
            results.append({
                "content": content,
                "source": location,
                "score": item.get("score"),
            })

    return redact_payload(results)
