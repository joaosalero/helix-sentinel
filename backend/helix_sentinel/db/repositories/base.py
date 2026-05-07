"""Shared repository primitives for persistence adapters."""

from typing import TypeVar

from sqlalchemy.ext.asyncio import AsyncSession

ModelT = TypeVar("ModelT")


class Repository[ModelT]:
    """Small base repository that keeps transaction ownership outside adapters."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
