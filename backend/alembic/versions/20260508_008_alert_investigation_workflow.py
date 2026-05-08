"""Add lightweight detection alert investigation workflow fields.

Revision ID: 20260508_008
Revises: 20260508_007
Create Date: 2026-05-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "20260508_008"
down_revision: str | None = "20260508_007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add analyst workflow metadata to persisted detection alerts."""
    op.add_column(
        "detection_alerts",
        sa.Column("assigned_to", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "detection_alerts",
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "detection_alerts",
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "detection_alerts",
        sa.Column("disposition", sa.String(length=120), nullable=True),
    )
    op.add_column(
        "detection_alerts",
        sa.Column("investigation_note", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_detection_alerts_assigned_status",
        "detection_alerts",
        ["assigned_to", "status"],
    )


def downgrade() -> None:
    """Remove analyst workflow metadata from persisted detection alerts."""
    op.drop_index("ix_detection_alerts_assigned_status", table_name="detection_alerts")
    op.drop_column("detection_alerts", "investigation_note")
    op.drop_column("detection_alerts", "disposition")
    op.drop_column("detection_alerts", "closed_at")
    op.drop_column("detection_alerts", "acknowledged_at")
    op.drop_column("detection_alerts", "assigned_to")
