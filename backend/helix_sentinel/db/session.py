"""Async SQLAlchemy engine and session factory wiring."""

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from helix_sentinel.core.config import get_settings

settings = get_settings()


def create_engine(database_url: str) -> AsyncEngine:
    """Create the async database engine used by PostgreSQL-backed adapters."""
    return create_async_engine(database_url, pool_pre_ping=True)


def create_session_factory(database_url: str) -> async_sessionmaker[AsyncSession]:
    """Create an async session factory for the configured database URL."""
    return async_sessionmaker(create_engine(database_url), expire_on_commit=False)


AsyncSessionFactory = create_session_factory(str(settings.database_url))


async def get_db_session() -> AsyncIterator[AsyncSession]:
    """Yield an async database session for request-scoped dependencies."""
    async with AsyncSessionFactory() as session:
        yield session
