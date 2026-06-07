from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi.templating import Jinja2Templates

from lighthouse_firewall_auto_allow.config import get_settings

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def format_local_datetime(value: datetime | None) -> str:
    if value is None:
        return "-"

    source = value
    if source.tzinfo is None:
        source = source.replace(tzinfo=UTC)

    try:
        target_tz = ZoneInfo(get_settings().display_timezone)
    except ZoneInfoNotFoundError:
        target_tz = timezone(timedelta(hours=8), name="Asia/Shanghai")

    return source.astimezone(target_tz).strftime("%Y-%m-%d %H:%M:%S")


templates.env.filters["local_dt"] = format_local_datetime
