"""IOC and enrichment persistence models."""

from typing import Any

from sqlalchemy import Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from helix_sentinel.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Indicator(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Indicator of compromise with enrichment metadata."""

    __tablename__ = "threat_indicators"
    __table_args__ = (
        UniqueConstraint("indicator_type", "value_hash"),
        Index("ix_threat_indicators_type_confidence", "indicator_type", "confidence"),
    )

    indicator_type: Mapped[str] = mapped_column(String(80), nullable=False)
    value_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    display_value: Mapped[str] = mapped_column(String(500), nullable=False)
    confidence: Mapped[int] = mapped_column(nullable=False, default=50)
    source: Mapped[str] = mapped_column(String(160), nullable=False)
    enrichment: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

