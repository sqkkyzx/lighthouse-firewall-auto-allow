from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class ClientTarget(Base):
    __tablename__ = "client_targets"

    client_id: Mapped[str] = mapped_column(String(48), ForeignKey("clients.id"), primary_key=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"), primary_key=True)


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[str] = mapped_column(String(48), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), default="active", nullable=False)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    platform: Mapped[str] = mapped_column(String(16), nullable=False)
    frequency_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    ip_mode: Mapped[str] = mapped_column(String(8), nullable=False)
    allow_ipv6_prefix: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False)
    port: Mapped[str] = mapped_column(String(64), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_ipv4: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_ipv6: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
    )
    last_report_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    targets: Mapped[list[Target]] = relationship(
        secondary="client_targets",
        back_populates="clients",
    )
    reports: Mapped[list[Report]] = relationship(
        back_populates="client",
        cascade="all, delete-orphan",
    )
    firewall_events: Mapped[list[FirewallEvent]] = relationship(
        back_populates="client",
        cascade="all, delete-orphan",
    )


class Target(Base):
    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("region", "instance_id", name="uq_targets_region_instance"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    region: Mapped[str] = mapped_column(String(32), nullable=False)
    instance_id: Mapped[str] = mapped_column(String(64), nullable=False)
    alias: Mapped[str] = mapped_column(String(100), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
    )

    clients: Mapped[list[Client]] = relationship(
        secondary="client_targets",
        back_populates="targets",
    )


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_id: Mapped[str] = mapped_column(String(48), ForeignKey("clients.id"), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ipv4: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ipv6: Mapped[str | None] = mapped_column(String(128), nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )

    client: Mapped[Client] = relationship(back_populates="reports")


class FirewallEvent(Base):
    __tablename__ = "firewall_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_id: Mapped[str] = mapped_column(String(48), ForeignKey("clients.id"), nullable=False)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )

    client: Mapped[Client] = relationship(back_populates="firewall_events")
    target: Mapped[Target] = relationship()


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )
