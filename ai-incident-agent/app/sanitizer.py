
import re


MAX_LOG_LENGTH = 2000


def sanitize_log_entry(log: str) -> str:
    """
    Normalize untrusted log content before analysis.

    This reduces malformed input but does not guarantee
    protection against prompt injection.
    """

    if not isinstance(log, str):
        raise TypeError("Log entry must be a string")

    
    log = "".join(
        char for char in log
        if char.isprintable() or char in "\t"
    )

    
    log = re.sub(r"[ \t]+", " ", log).strip()

    
    log = log[:MAX_LOG_LENGTH]

    return log


def sanitize_logs(logs: list[str]) -> list[str]:
    """
    Sanitize a collection of application log entries.
    """

    return [
        sanitize_log_entry(log)
        for log in logs
    ]
