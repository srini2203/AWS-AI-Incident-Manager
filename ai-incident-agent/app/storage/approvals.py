from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from app.config import (
    APPROVAL_TABLE_NAME,
    APPROVAL_TTL_HOURS,
    AWS_API_TIMEOUT_SECONDS,
    AWS_REGION,
)
from app.models import ApprovalRequest, ApprovalStatus, utc_now


class ApprovalStorageError(RuntimeError):
    pass


class ApprovalNotFoundError(ApprovalStorageError):
    pass


class ApprovalAlreadyDecidedError(ApprovalStorageError):
    pass


class ApprovalExpiredError(ApprovalStorageError):
    pass


class ApprovalConflictError(ApprovalStorageError):
    pass


class ApprovalRepository:
    def __init__(
        self,
        table: Any | None = None,
        table_name: str | None = None,
        dynamodb_resource: Any | None = None,
    ) -> None:
        self.table_name = table_name or APPROVAL_TABLE_NAME

        if not self.table_name:
            raise ValueError(
                "APPROVAL_TABLE_NAME must be configured"
            )

        if table is not None:
            self.table = table
            return

        resource = dynamodb_resource or boto3.resource(
            "dynamodb",
            region_name=AWS_REGION,
            config=Config(
                connect_timeout=AWS_API_TIMEOUT_SECONDS,
                read_timeout=AWS_API_TIMEOUT_SECONDS,
                retries={
                    "max_attempts": 3,
                    "mode": "standard",
                },
            ),
        )

        self.table = resource.Table(self.table_name)

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )

            if parsed.tzinfo is None:
                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

            return parsed.astimezone(timezone.utc)

        except (ValueError, AttributeError) as exc:
            raise ValueError(
                "Invalid approval timestamp"
            ) from exc

    @staticmethod
    def _to_epoch(value: datetime) -> int:
        return int(value.timestamp())

    @staticmethod
    def _normalize_decision(decision: str) -> ApprovalStatus:
        normalized = decision.strip().upper()

        if normalized == "APPROVE":
            normalized = "APPROVED"

        if normalized == "REJECT":
            normalized = "REJECTED"

        try:
            result = ApprovalStatus(normalized)
        except ValueError as exc:
            raise ValueError(
                "Decision must be APPROVED or REJECTED"
            ) from exc

        if result not in {
            ApprovalStatus.APPROVED,
            ApprovalStatus.REJECTED,
        }:
            raise ValueError(
                "Only APPROVED and REJECTED are valid decisions"
            )

        return result

    def _prepare_request(
        self,
        approval: ApprovalRequest,
    ) -> tuple[ApprovalRequest, int]:
        if not isinstance(approval, ApprovalRequest):
            raise TypeError(
                "approval must be an ApprovalRequest instance"
            )

        if not approval.approval_id.strip():
            raise ValueError("approval_id is required")

        if not approval.incident_id.strip():
            raise ValueError("incident_id is required")

        if not approval.action.strip():
            raise ValueError("action is required")

        if not approval.requested_by.strip():
            raise ValueError("requested_by is required")

        if approval.status != ApprovalStatus.PENDING:
            raise ValueError(
                "New approval requests must have PENDING status"
            )

        created_at = self._parse_datetime(
            approval.created_at or utc_now()
        )

        if approval.expires_at:
            expires_at = self._parse_datetime(
                approval.expires_at
            )
        else:
            expires_at = created_at + timedelta(
                hours=APPROVAL_TTL_HOURS
            )

            approval.expires_at = expires_at.isoformat()

        if expires_at <= created_at:
            raise ValueError(
                "Approval expiry must be after creation time"
            )

        approval.created_at = created_at.isoformat()

        return approval, self._to_epoch(expires_at)

    @staticmethod
    def _to_model(item: dict[str, Any]) -> ApprovalRequest:
        status = ApprovalStatus(
            str(item.get("status", "PENDING"))
        )

        expires_at_epoch = int(
            item.get("expires_at_epoch", 0)
        )

        if (
            status == ApprovalStatus.PENDING
            and expires_at_epoch
            and expires_at_epoch <= int(
                datetime.now(timezone.utc).timestamp()
            )
        ):
            status = ApprovalStatus.EXPIRED

        return ApprovalRequest(
            approval_id=str(item["approval_id"]),
            incident_id=str(item["incident_id"]),
            action=str(item["action"]),
            requested_by=str(item["requested_by"]),
            status=status,
            created_at=str(item["created_at"]),
            expires_at=str(item.get("expires_at", "")),
            reviewed_by=str(item.get("reviewed_by", "")),
            reviewed_at=str(item.get("reviewed_at", "")),
            review_reason=str(item.get("review_reason", "")),
        )

    def create(
        self,
        approval: ApprovalRequest,
    ) -> ApprovalRequest:
        approval, expires_at_epoch = self._prepare_request(
            approval
        )

        item = {
            "approval_id": approval.approval_id,
            "incident_id": approval.incident_id,
            "action": approval.action,
            "requested_by": approval.requested_by,
            "status": approval.status.value,
            "created_at": approval.created_at,
            "expires_at": approval.expires_at,
            "expires_at_epoch": expires_at_epoch,
            "reviewed_by": "",
            "reviewed_at": "",
            "review_reason": "",
        }

        try:
            self.table.put_item(
                Item=item,
                ConditionExpression=(
                    "attribute_not_exists(approval_id)"
                ),
            )

        except ClientError as exc:
            error_code = exc.response.get(
                "Error", {}
            ).get("Code", "")

            if error_code == "ConditionalCheckFailedException":
                raise ApprovalConflictError(
                    "An approval with this ID already exists"
                ) from exc

            raise ApprovalStorageError(
                "Unable to create approval record"
            ) from exc

        return approval

    def get(
        self,
        approval_id: str,
    ) -> ApprovalRequest:
        if not approval_id or not approval_id.strip():
            raise ValueError("approval_id is required")

        try:
            response = self.table.get_item(
                Key={
                    "approval_id": approval_id,
                },
                ConsistentRead=True,
            )

        except ClientError as exc:
            raise ApprovalStorageError(
                "Unable to retrieve approval record"
            ) from exc

        item = response.get("Item")

        if not item:
            raise ApprovalNotFoundError(
                "Approval request was not found"
            )

        approval = self._to_model(item)

        if approval.status == ApprovalStatus.EXPIRED:
            self._mark_expired(approval_id)

        return approval

    def _mark_expired(
        self,
        approval_id: str,
    ) -> None:
        now = int(
            datetime.now(timezone.utc).timestamp()
        )

        try:
            self.table.update_item(
                Key={
                    "approval_id": approval_id,
                },
                UpdateExpression="SET #status = :expired",
                ConditionExpression=(
                    "#status = :pending "
                    "AND expires_at_epoch <= :now"
                ),
                ExpressionAttributeNames={
                    "#status": "status",
                },
                ExpressionAttributeValues={
                    ":pending": "PENDING",
                    ":expired": "EXPIRED",
                    ":now": now,
                },
            )

        except ClientError as exc:
            error_code = exc.response.get(
                "Error", {}
            ).get("Code", "")

            if error_code != "ConditionalCheckFailedException":
                raise ApprovalStorageError(
                    "Unable to update expired approval"
                ) from exc

    def decide(
        self,
        approval_id: str,
        decision: str,
        reviewed_by: str,
        reason: str = "",
    ) -> ApprovalRequest:
        if not approval_id or not approval_id.strip():
            raise ValueError("approval_id is required")

        if not reviewed_by or not reviewed_by.strip():
            raise ValueError("reviewed_by is required")

        normalized_decision = self._normalize_decision(
            decision
        )

        now = datetime.now(timezone.utc)
        now_epoch = int(now.timestamp())

        try:
            response = self.table.update_item(
                Key={
                    "approval_id": approval_id,
                },
                UpdateExpression=(
                    "SET #status = :decision, "
                    "reviewed_by = :reviewed_by, "
                    "reviewed_at = :reviewed_at, "
                    "review_reason = :reason"
                ),
                ConditionExpression=(
                    "#status = :pending "
                    "AND expires_at_epoch > :now"
                ),
                ExpressionAttributeNames={
                    "#status": "status",
                },
                ExpressionAttributeValues={
                    ":pending": "PENDING",
                    ":decision": normalized_decision.value,
                    ":reviewed_by": reviewed_by.strip(),
                    ":reviewed_at": now.isoformat(),
                    ":reason": reason.strip()[:2000],
                    ":now": now_epoch,
                },
                ReturnValues="ALL_NEW",
            )

            item = response.get("Attributes")

            if not item:
                raise ApprovalStorageError(
                    "Approval decision returned no record"
                )

            return self._to_model(item)

        except ClientError as exc:
            error_code = exc.response.get(
                "Error", {}
            ).get("Code", "")

            if error_code != "ConditionalCheckFailedException":
                raise ApprovalStorageError(
                    "Unable to record approval decision"
                ) from exc

            current = self.get(approval_id)

            if current.status == ApprovalStatus.EXPIRED:
                raise ApprovalExpiredError(
                    "Approval request has expired"
                ) from exc

            if current.status != ApprovalStatus.PENDING:
                raise ApprovalAlreadyDecidedError(
                    "Approval request has already been decided"
                ) from exc

            raise ApprovalConflictError(
                "Approval request changed during the decision"
            ) from exc


def create_approval(
    approval: ApprovalRequest,
    repository: ApprovalRepository | None = None,
) -> ApprovalRequest:
    storage = repository or ApprovalRepository()
    return storage.create(approval)


def get_approval(
    approval_id: str,
    repository: ApprovalRepository | None = None,
) -> ApprovalRequest:
    storage = repository or ApprovalRepository()
    return storage.get(approval_id)


def decide_approval(
    approval_id: str,
    decision: str,
    reviewed_by: str,
    reason: str = "",
    repository: ApprovalRepository | None = None,
) -> ApprovalRequest:
    storage = repository or ApprovalRepository()

    return storage.decide(
        approval_id=approval_id,
        decision=decision,
        reviewed_by=reviewed_by,
        reason=reason,
    )