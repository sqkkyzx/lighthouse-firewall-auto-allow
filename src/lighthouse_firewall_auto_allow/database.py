from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from lighthouse_firewall_auto_allow.config import get_settings
from lighthouse_firewall_auto_allow.models import Base


def _connect_args(database_url: str) -> dict[str, bool]:
    if database_url.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


def _ensure_sqlite_parent(database_url: str) -> None:
    if not database_url.startswith("sqlite:///"):
        return
    raw_path = database_url.removeprefix("sqlite:///")
    if raw_path in {":memory:", ""}:
        return
    Path(raw_path).parent.mkdir(parents=True, exist_ok=True)


settings = get_settings()
_ensure_sqlite_parent(settings.database_url)
engine = create_engine(settings.database_url, connect_args=_connect_args(settings.database_url))
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def create_db_and_tables() -> None:
    Base.metadata.create_all(bind=engine)
    _apply_compatible_migrations()


def _apply_compatible_migrations() -> None:
    inspector = inspect(engine)
    if "clients" not in inspector.get_table_names():
        return
    client_columns = {column["name"] for column in inspector.get_columns("clients")}
    if "allow_ipv6_prefix" in client_columns:
        return
    if engine.dialect.name == "sqlite":
        statement = "ALTER TABLE clients ADD COLUMN allow_ipv6_prefix BOOLEAN NOT NULL DEFAULT 0"
    else:
        statement = (
            "ALTER TABLE clients ADD COLUMN allow_ipv6_prefix BOOLEAN NOT NULL DEFAULT false"
        )
    with engine.begin() as connection:
        connection.execute(text(statement))


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
