"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-04
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "clients",
        sa.Column("id", sa.String(length=48), primary_key=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("platform", sa.String(length=16), nullable=False),
        sa.Column("frequency_minutes", sa.Integer(), nullable=False),
        sa.Column("ip_mode", sa.String(length=8), nullable=False),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("port", sa.String(length=64), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("last_ipv4", sa.String(length=64), nullable=True),
        sa.Column("last_ipv6", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_report_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "targets",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("region", sa.String(length=32), nullable=False),
        sa.Column("instance_id", sa.String(length=64), nullable=False),
        sa.Column("alias", sa.String(length=100), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("region", "instance_id", name="uq_targets_region_instance"),
    )
    op.create_table(
        "client_targets",
        sa.Column("client_id", sa.String(length=48), sa.ForeignKey("clients.id"), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), primary_key=True),
    )
    op.create_table(
        "reports",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("client_id", sa.String(length=48), sa.ForeignKey("clients.id"), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("ipv4", sa.String(length=64), nullable=True),
        sa.Column("ipv6", sa.String(length=128), nullable=True),
        sa.Column("agent_version", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "firewall_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("client_id", sa.String(length=48), sa.ForeignKey("clients.id"), nullable=False),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("firewall_events")
    op.drop_table("reports")
    op.drop_table("client_targets")
    op.drop_table("targets")
    op.drop_table("clients")
