import logging
import unittest
from datetime import datetime, timezone

from app.models import ApprovalStatus, Incident
from app.workflow.approval import ApprovalService
from app.workflow.audit import AuditLogger


class FakeRepository:
    def __init__(self):
        self.items = {}

    def create(self, approval):
        self.items[approval.approval_id] = approval
        return approval

    def decide(self, approval_id, decision, reviewed_by, reason=""):
        item = self.items[approval_id]
        item.status = ApprovalStatus.APPROVED if decision.upper() in {"APPROVE", "APPROVED"} else ApprovalStatus.REJECTED
        item.reviewed_by = reviewed_by
        item.reviewed_at = datetime.now(timezone.utc).isoformat()
        item.review_reason = reason
        return item


class FakeNotifications:
    def send_approval_request(self, incident, approval):
        return {"status": "SENT", "message_id": "message-1"}


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        logger = logging.getLogger("approval-test")
        logger.handlers = [logging.NullHandler()]
        logger.propagate = False
        self.audit = AuditLogger(logger=logger)
        self.repository = FakeRepository()
        self.service = ApprovalService(
            repository=self.repository,
            notification_service=FakeNotifications(),
            audit_logger=self.audit,
        )

    def test_creates_pending_approval(self):
        incident = Incident("alarm", "HIGH", "i-123", "issue")
        approval = self.service.create_request(incident, "Scale the ASG")
        self.assertEqual(approval.status, ApprovalStatus.PENDING)
        self.assertEqual(approval.incident_id, incident.event_id)

    def test_records_approval_decision(self):
        incident = Incident("alarm", "HIGH", "i-123", "issue")
        approval = self.service.create_request(incident, "Scale the ASG")
        decided = self.service.decide_request(approval.approval_id, "APPROVE", "reviewer", "Reviewed")
        self.assertEqual(decided.status, ApprovalStatus.APPROVED)
        self.assertEqual(decided.reviewed_by, "reviewer")


if __name__ == "__main__":
    unittest.main()
