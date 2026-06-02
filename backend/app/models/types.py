"""Cross-database column types (PostgreSQL + SQLite)."""
import uuid
from typing import Any, Optional

from sqlalchemy import JSON, String, TypeDecorator
from sqlalchemy.dialects.postgresql import JSONB


class GUID(TypeDecorator):
    """UUID stored as string — works on SQLite and PostgreSQL."""

    impl = String(36)
    cache_ok = True

    def process_bind_param(self, value: Optional[Any], dialect) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return str(value)
        return str(value)

    def process_result_value(self, value: Optional[Any], dialect) -> Optional[uuid.UUID]:
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))


class FlexibleJSON(TypeDecorator):
    """JSONB on PostgreSQL, JSON on SQLite."""

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


def enum_column(enum_class, **kwargs):
    """Enum column that persists .value strings (SQLite-safe)."""
    from sqlalchemy import Enum
    return Enum(
        enum_class,
        values_callable=lambda x: [e.value for e in x],
        native_enum=False,
        **kwargs,
    )
