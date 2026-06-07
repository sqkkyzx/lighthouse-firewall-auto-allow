FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV UV_COMPILE_BYTECODE=1

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:0.7.8 /uv /usr/local/bin/uv
COPY pyproject.toml README.md /app/
COPY src /app/src
COPY alembic.ini /app/alembic.ini
COPY migrations /app/migrations

RUN uv sync --no-dev

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "lighthouse_firewall_auto_allow.main:app", "--host", "0.0.0.0", "--port", "8000"]
