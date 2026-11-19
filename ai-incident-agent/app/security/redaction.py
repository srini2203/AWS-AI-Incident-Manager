from __future__ import annotations

import re
from typing import Any


REDACTED = "[REDACTED]"

SECRET_PATTERNS = [
    re.compile(
        r"(?i)(aws_secret_access_key\s*[:=]\s*)[^\s,;\"']+"
    ),
    re.compile(
        r"(?i)(aws_session_token\s*[:=]\s*)[^\s,;\"']+"
    ),
    re.compile(
        r"(?i)(aws_access_key_id\s*[:=]\s*)[A-Z0-9]{16,}"
    ),
    re.compile(
        r"(?i)(password\s*[:=]\s*)[^\s,;\"']+"
    ),
    re.compile(
        r"(?i)(passwd\s*[:=]\s*)[^\s,;\"']+"
    ),
    re.compile(
        r"(?i)(client_secret\s*[:=]\s*)[^\s,;\"']+"
    ),
    re.compile(
        r"(?i)(api[_-]?key\s*[:=]\s*)[^\s,;\"']+"
    ),
    re.compile(
        r"(?i)(access[_-]?token\s*[:=]\s*)[^\s,;\"']+"
    ),
    re.compile(
        r"(?i)(refresh[_-]?token\s*[:=]\s*)[^\s,;\"']+"
    ),
    re.compile(
        r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/=-]+"
    ),
    re.compile(
        r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"
    ),
    re.compile(
        r"(?i)(x-api-key\s*:\s*)[^\s,;\"']+"
    ),
    re.compile(
        r"(?i)(set-cookie\s*:\s*)[^\r\n]+"
    ),
    re.compile(
        r"(?i)(cookie\s*:\s*)[^\r\n]+"
    ),
]

AWS_ACCESS_KEY_PATTERN = re.compile(
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
)

PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    r".*?"
    r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    re.DOTALL,
)

JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\."
    r"[A-Za-z0-9_-]{10,}\."
    r"[A-Za-z0-9_-]{10,}\b"
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

SENSITIVE_FIELD_NAMES = {
    "password",
    "passwd",
    "secret",
    "client_secret",
    "clientsecret",
    "secret_access_key",
    "aws_secret_access_key",
    "aws_session_token",
    "session_token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "authorization",
    "private_key",
    "privatekey",
    "credential",
    "credentials",
    "connection_string",
}


def _normalize_field_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def is_sensitive_field(name: str) -> bool:
    normalized = _normalize_field_name(name)

    if normalized in {
        _normalize_field_name(item)
        for item in SENSITIVE_FIELD_NAMES
    }:
        return True

    return any(
        marker in normalized
        for marker in (
            "password",
            "passwd",
            "secret",
            "token",
            "apikey",
            "privatekey",
            "credential",
        )
    )


def redact_text(value: str, redact_emails: bool = True) -> str:
    if not isinstance(value, str) or not value:
        return value

    result = PRIVATE_KEY_PATTERN.sub(REDACTED, value)

    for pattern in SECRET_PATTERNS:
        result = pattern.sub(
            lambda match: match.group(1) + REDACTED,
            result,
        )

    result = AWS_ACCESS_KEY_PATTERN.sub(
        REDACTED,
        result,
    )

    result = JWT_PATTERN.sub(
        REDACTED,
        result,
    )

    if redact_emails:
        result = EMAIL_PATTERN.sub(
            REDACTED,
            result,
        )

    return result


def redact_value(
    value: Any,
    redact_emails: bool = True,
) -> Any:
    if isinstance(value, str):
        return redact_text(
            value,
            redact_emails=redact_emails,
        )

    if isinstance(value, bytes):
        decoded = value.decode("utf-8", errors="replace")
        return redact_text(
            decoded,
            redact_emails=redact_emails,
        )

    if isinstance(value, dict):
        return {
            str(key): (
                REDACTED
                if is_sensitive_field(str(key))
                else redact_value(
                    item,
                    redact_emails=redact_emails,
                )
            )
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            redact_value(
                item,
                redact_emails=redact_emails,
            )
            for item in value
        ]

    if isinstance(value, tuple):
        return tuple(
            redact_value(
                item,
                redact_emails=redact_emails,
            )
            for item in value
        )

    return value


def redact_mapping(
    value: dict[str, Any],
    redact_emails: bool = True,
) -> dict[str, Any]:
    result = redact_value(
        value,
        redact_emails=redact_emails,
    )

    if not isinstance(result, dict):
        raise TypeError("Expected a dictionary")

    return result


def redact_payload(
    value: Any,
    redact_emails: bool = True,
) -> Any:
    return redact_value(
        value,
        redact_emails=redact_emails,
    )


def redact_evidence(evidence: Any) -> dict[str, Any]:
    if hasattr(evidence, "to_dict"):
        payload = evidence.to_dict()
    elif isinstance(evidence, dict):
        payload = evidence
    else:
        raise TypeError(
            "Evidence must be a dictionary or expose to_dict()"
        )

    result = redact_payload(payload)

    if not isinstance(result, dict):
        raise TypeError("Sanitized evidence must be a dictionary")

    return result