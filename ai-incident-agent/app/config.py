import os
from functools import lru_cache


def get_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    normalized = value.strip().lower()

    if normalized in {"true", "1", "yes", "on"}:
        return True

    if normalized in {"false", "0", "no", "off"}:
        return False

    raise ValueError(f"{name} must be a valid boolean")


def get_int(
    name: str,
    default: int,
    minimum: int = 1,
    maximum: int = 2147483647,
) -> int:
    value = os.getenv(name)

    if value is None:
        return default

    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc

    if not minimum <= parsed <= maximum:
        raise ValueError(
            f"{name} must be between {minimum} and {maximum}"
        )

    return parsed


def get_float(
    name: str,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    value = os.getenv(name)

    if value is None:
        return default

    try:
        parsed = float(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc

    if not minimum <= parsed <= maximum:
        raise ValueError(
            f"{name} must be between {minimum} and {maximum}"
        )

    return parsed


def get_csv(name: str) -> list[str]:
    value = os.getenv(name, "")

    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


APP_NAME = "aws-ai-incident-triage-agent"
APP_ENV = os.getenv("APP_ENV", "production").strip().lower()

AWS_REGION = os.getenv("AWS_REGION", "ap-south-1").strip()

BEDROCK_MODEL_ID = os.getenv(
    "BEDROCK_MODEL_ID",
    "apac.amazon.nova-micro-v1:0",
).strip()

BEDROCK_MAX_TOKENS = get_int(
    "BEDROCK_MAX_TOKENS",
    1800,
    100,
    8192,
)

BEDROCK_TEMPERATURE = get_float(
    "BEDROCK_TEMPERATURE",
    0.1,
    0.0,
    1.0,
)

BEDROCK_TOP_P = get_float(
    "BEDROCK_TOP_P",
    0.9,
    0.0,
    1.0,
)

BEDROCK_GUARDRAIL_ID = os.getenv(
    "BEDROCK_GUARDRAIL_ID",
    "",
).strip()

BEDROCK_GUARDRAIL_VERSION = os.getenv(
    "BEDROCK_GUARDRAIL_VERSION",
    "",
).strip()

ENABLE_BEDROCK_GUARDRAILS = get_bool(
    "ENABLE_BEDROCK_GUARDRAILS",
    True,
)

BEDROCK_RETRY_ATTEMPTS = get_int(
    "BEDROCK_RETRY_ATTEMPTS",
    3,
    1,
    10,
)

BEDROCK_CONNECT_TIMEOUT_SECONDS = get_int(
    "BEDROCK_CONNECT_TIMEOUT_SECONDS",
    5,
    1,
    60,
)

BEDROCK_READ_TIMEOUT_SECONDS = get_int(
    "BEDROCK_READ_TIMEOUT_SECONDS",
    60,
    1,
    300,
)

BEDROCK_MAX_EVIDENCE_CHARS = get_int(
    "BEDROCK_MAX_EVIDENCE_CHARS",
    30000,
    1000,
    100000,
)

CLOUDWATCH_LOG_GROUPS = get_csv("CLOUDWATCH_LOG_GROUPS")

APP_LOG_GROUP = os.getenv(
    "APP_LOG_GROUP",
    "",
).strip()

if APP_LOG_GROUP and APP_LOG_GROUP not in CLOUDWATCH_LOG_GROUPS:
    CLOUDWATCH_LOG_GROUPS.insert(0, APP_LOG_GROUP)

CLOUDWATCH_LOG_LOOKBACK_MINUTES = get_int(
    "CLOUDWATCH_LOG_LOOKBACK_MINUTES",
    15,
    1,
    1440,
)

CLOUDWATCH_LOG_QUERY_TIMEOUT_SECONDS = get_int(
    "CLOUDWATCH_LOG_QUERY_TIMEOUT_SECONDS",
    30,
    1,
    120,
)

MAX_LOG_ENTRIES = get_int(
    "MAX_LOG_ENTRIES",
    200,
    1,
    1000,
)

MAX_LOG_ENTRY_LENGTH = get_int(
    "MAX_LOG_ENTRY_LENGTH",
    4000,
    100,
    20000,
)

METRICS_LOOKBACK_MINUTES = get_int(
    "METRICS_LOOKBACK_MINUTES",
    15,
    1,
    1440,
)

METRIC_PERIOD_SECONDS = get_int(
    "METRIC_PERIOD_SECONDS",
    60,
    60,
    3600,
)

MAX_METRIC_DATAPOINTS = get_int(
    "MAX_METRIC_DATAPOINTS",
    100,
    1,
    1000,
)

TARGET_GROUP_ARN = os.getenv(
    "TARGET_GROUP_ARN",
    "",
).strip()

LOAD_BALANCER_ARN = os.getenv(
    "LOAD_BALANCER_ARN",
    "",
).strip()

SNS_TOPIC_ARN = os.getenv(
    "SNS_TOPIC_ARN",
    "",
).strip()

ENABLE_SNS_NOTIFICATIONS = get_bool(
    "ENABLE_SNS_NOTIFICATIONS",
    True,
)

APPROVAL_TABLE_NAME = os.getenv(
    "APPROVAL_TABLE_NAME",
    "",
).strip()

APPROVAL_TTL_HOURS = get_int(
    "APPROVAL_TTL_HOURS",
    24,
    1,
    168,
)

APPROVAL_API_URL = os.getenv(
    "APPROVAL_API_URL",
    "",
).strip()

AUDIT_LOG_GROUP = os.getenv(
    "AUDIT_LOG_GROUP",
    "/aws/lambda/aws-ai-incident-triage-agent-audit",
).strip()

AUDIT_LOG_LEVEL = os.getenv(
    "AUDIT_LOG_LEVEL",
    "INFO",
).strip().upper()

LAMBDA_TIMEOUT_SECONDS = get_int(
    "LAMBDA_TIMEOUT_SECONDS",
    60,
    5,
    900,
)

AWS_API_TIMEOUT_SECONDS = get_int(
    "AWS_API_TIMEOUT_SECONDS",
    10,
    1,
    60,
)

INVESTIGATION_MAX_CONCURRENCY = get_int(
    "INVESTIGATION_MAX_CONCURRENCY",
    4,
    1,
    20,
)

PROMPT_VERSION = os.getenv(
    "PROMPT_VERSION",
    "1.0",
).strip()

if not AWS_REGION:
    raise ValueError("AWS_REGION cannot be empty")

if not BEDROCK_MODEL_ID:
    raise ValueError("BEDROCK_MODEL_ID cannot be empty")

if ENABLE_BEDROCK_GUARDRAILS:
    if not BEDROCK_GUARDRAIL_ID:
        raise ValueError(
            "BEDROCK_GUARDRAIL_ID is required when Guardrails are enabled"
        )

    if not BEDROCK_GUARDRAIL_VERSION:
        raise ValueError(
            "BEDROCK_GUARDRAIL_VERSION is required when Guardrails are enabled"
        )

if ENABLE_SNS_NOTIFICATIONS and not SNS_TOPIC_ARN and APP_ENV == "production":
    raise ValueError(
        "SNS_TOPIC_ARN is required for production notifications"
    )

if APP_ENV == "production" and not APPROVAL_TABLE_NAME:
    raise ValueError(
        "APPROVAL_TABLE_NAME is required in production"
    )

if AUDIT_LOG_LEVEL not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
    raise ValueError("AUDIT_LOG_LEVEL is invalid")


@lru_cache(maxsize=1)
def get_runtime_identity() -> dict[str, str]:
    return {
        "application": APP_NAME,
        "environment": APP_ENV,
        "region": AWS_REGION,
        "model_id": BEDROCK_MODEL_ID,
        "prompt_version": PROMPT_VERSION,
    }