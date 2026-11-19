from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from app.security.redaction import redact_payload
from app.workflow.orchestrator import (
    IncidentWorkflowOrchestrator,
    InvestigationError,
)


logger = logging.getLogger("incident_agent")


def load_event(path: str | None) -> dict[str, Any]:
    if path:
        try:
            content = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(
                f"Unable to read event file: {path}"
            ) from exc
    else:
        if sys.stdin.isatty():
            raise ValueError(
                "Provide an event JSON file or pipe JSON through standard input"
            )

        content = sys.stdin.read()

    try:
        event = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "Input does not contain valid JSON"
        ) from exc

    if not isinstance(event, dict):
        raise ValueError(
            "Incident event must be a JSON object"
        )

    return event


def write_output(
    result: dict[str, Any],
    output_path: str | None,
) -> None:
    sanitized = redact_payload(result)

    serialized = json.dumps(
        sanitized,
        ensure_ascii=False,
        indent=2,
        default=str,
    )

    if output_path:
        destination = Path(output_path)

        try:
            destination.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            destination.write_text(
                serialized + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            raise RuntimeError(
                f"Unable to write investigation report: {output_path}"
            ) from exc

    print(serialized)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aws-ai-incident-triage",
        description=(
            "Investigate AWS infrastructure incidents using "
            "CloudWatch diagnostics and Amazon Bedrock."
        ),
    )

    parser.add_argument(
        "event_file",
        nargs="?",
        help="Path to a JSON incident event file",
    )

    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Optional path to save the investigation report",
    )

    parser.add_argument(
        "--correlation-id",
        default=None,
        help="Optional investigation correlation identifier",
    )

    parser.add_argument(
        "--log-level",
        choices=[
            "DEBUG",
            "INFO",
            "WARNING",
            "ERROR",
        ],
        default="INFO",
        help="Application logging level",
    )

    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()

    logging.basicConfig(
        level=getattr(logging, arguments.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )

    try:
        event = load_event(arguments.event_file)

        orchestrator = IncidentWorkflowOrchestrator()

        result = orchestrator.investigate(
            event=event,
            correlation_id=arguments.correlation_id,
        )

        write_output(
            result=result,
            output_path=arguments.output,
        )

        return 0

    except (ValueError, InvestigationError) as exc:
        logger.error(
            "Incident investigation failed: %s",
            str(exc),
        )
        return 1

    except KeyboardInterrupt:
        logger.error("Investigation interrupted")
        return 130

    except Exception:
        logger.exception(
            "Unexpected incident investigation failure"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())