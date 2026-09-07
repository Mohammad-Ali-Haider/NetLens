FROM ghcr.io/astral-sh/uv:0.10.2 AS uv
FROM python:3.12-slim
COPY --from=uv /uv /usr/local/bin/uv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_COMPILE_BYTECODE=1
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY src ./src
RUN uv sync --locked --no-dev && groupadd --gid 10001 netlens && useradd --uid 10001 --gid 10001 --no-create-home netlens
COPY alembic.ini ./
COPY migrations ./migrations
COPY demo ./demo
COPY evaluation/manifest.json ./evaluation/manifest.json
RUN mkdir -p /app/data/captures && chown -R 10001:10001 /app/data
ENV PATH="/app/.venv/bin:$PATH"
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "netlens.api:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
