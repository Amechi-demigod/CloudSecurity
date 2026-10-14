# syntax=docker/dockerfile:1
# Production image for the CNAPP API: multi-stage, non-root, gunicorn + uvicorn workers.

ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY requirements.txt .
RUN pip install -r requirements.txt

FROM python:${PYTHON_VERSION}-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH \
    # Local/docker-compose default; production sets DATABASE_URL to PostgreSQL.
    DATABASE_URL=sqlite:////data/cnapp.db \
    PORT=8000 \
    WEB_CONCURRENCY=2
RUN groupadd --gid 10001 cnapp \
    && useradd --uid 10001 --gid cnapp --no-create-home --shell /usr/sbin/nologin cnapp \
    && mkdir -p /data && chown cnapp:cnapp /data
WORKDIR /app
COPY --from=build /opt/venv /opt/venv
COPY --chown=root:root alembic.ini gunicorn.conf.py ./
COPY --chown=root:root migrations ./migrations
COPY --chown=root:root app ./app

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\", \"8000\")}/api/health', timeout=4)"]
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app.main:app"]
