import os

AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")

BEDROCK_MODEL_ID = os.getenv(
    "BEDROCK_MODEL_ID",
    "apac.amazon.nova-micro-v1:0"
)

BEDROCK_MAX_TOKENS = 1000
BEDROCK_TEMPERATURE = 0.2