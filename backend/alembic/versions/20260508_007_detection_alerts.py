"""Create detection alert lifecycle table.

Revision ID: 20260508_007
Revises: 20260508_006
Create Date: 2026-05-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "20260508_007"
down_revision: str | None = "20260508_006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create persisted detection alert lifecycle records."""
    op.create_table(
        "detection_alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=80), nullable=False),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("severity", sa.String(length=40), nullable=False),
        sa.Column("category", sa.String(length=80), nullable=False),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("source_name", sa.String(length=120), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("matched_selections", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("correlation_id", sa.String(length=80), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["event_id"], ["normalized_security_events.id"]),
        sa.ForeignKeyConstraint(["rule_id"], ["detection_rules_v2.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("rule_id", "event_id", name="uq_detection_alerts_rule_event"),
    )
    op.create_index(
        "ix_detection_alerts_tenant_status_created",
        "detection_alerts",
        ["tenant_id", "status", "created_at"],
    )
    op.create_index(
        "ix_detection_alerts_rule_created",
        "detection_alerts",
        ["rule_id", "created_at"],
    )
    op.create_index("ix_detection_alerts_event", "detection_alerts", ["event_id"])


def downgrade() -> None:
    """Drop persisted detection alert lifecycle records."""
    op.drop_index("ix_detection_alerts_event", table_name="detection_alerts")
    op.drop_index("ix_detection_alerts_rule_created", table_name="detection_alerts")
    op.drop_index("ix_detection_alerts_tenant_status_created", table_name="detection_alerts")
    op.drop_table("detection_alerts")
