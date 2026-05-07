"""Security validation run models."""

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from helix_sentinel.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ValidationRun(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Detection validation or simulation execution summary."""

    __tablename__ = "validation_runs"
    __table_args__ = (Index("ix_validation_runs_status_started", "status", "started_at"),)

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

