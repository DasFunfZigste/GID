FROM python:3.12-slim-bookworm

ARG VERSION=0.1.1
LABEL org.opencontainers.image.title="GID — Get It Done" \
    org.opencontainers.image.description="A small, self-hosted task and reminder application" \
    org.opencontainers.image.source="https://github.com/DasFunfZigste/GID" \
    org.opencontainers.image.version="${VERSION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    GID_DATA_DIR=/data \
    GID_TIMEZONE=America/New_York

RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && python -c "from zoneinfo import ZoneInfo; ZoneInfo('America/New_York')" \
    && useradd --uid 10001 --create-home gid \
    && mkdir -p /data \
    && chown 10001:10001 /data

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=10001:10001 gid ./gid

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=4 \
    CMD python -c "import json, urllib.request; r = urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3); assert json.load(r)['status'] == 'ok'"

CMD ["uvicorn", "gid.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log"]
