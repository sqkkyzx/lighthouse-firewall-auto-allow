from __future__ import annotations

from sqlalchemy import create_engine, inspect, text

from lighthouse_firewall_auto_allow.database import _apply_compatible_migrations


def test_compatible_migration_adds_ipv6_prefix_column_to_existing_clients_table(
    monkeypatch,
) -> None:
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE clients (
                    id VARCHAR(48) PRIMARY KEY,
                    status VARCHAR(16) NOT NULL,
                    token_hash VARCHAR(128) NOT NULL,
                    platform VARCHAR(16) NOT NULL,
                    frequency_minutes INTEGER NOT NULL,
                    ip_mode VARCHAR(8) NOT NULL,
                    protocol VARCHAR(8) NOT NULL,
                    port VARCHAR(64) NOT NULL
                )
                """
            )
        )

    monkeypatch.setattr(
        "lighthouse_firewall_auto_allow.database.engine",
        engine,
    )

    _apply_compatible_migrations()

    columns = {column["name"] for column in inspect(engine).get_columns("clients")}
    assert "allow_ipv6_prefix" in columns
