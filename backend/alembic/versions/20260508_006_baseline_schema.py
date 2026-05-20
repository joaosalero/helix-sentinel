"""Create baseline application schema.

Revision ID: 20260508_006
Revises:
Create Date: 2026-05-08
"""

from collections.abc import Sequence

from sqlalchemy import Table

from alembic import op

from helix_sentinel.db.models import Base

revision: str = "20260508_006"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_EXCLUDED_TABLES = {"detection_alerts"}


def upgrade() -> None:
    """Create all baseline tables required before alert lifecycle migrations."""
    Base.metadata.create_all(bind=op.get_bind(), tables=_baseline_tables())


def downgrade() -> None:
    """Drop baseline tables in dependency-safe order."""
    for table in reversed(_baseline_tables()):
        table.drop(op.get_bind(), checkfirst=True)


def _baseline_tables() -> list[Table]:
    return [
        table
        for table in Base.metadata.sorted_tables
        if table.name not in _EXCLUDED_TABLES
    ]
