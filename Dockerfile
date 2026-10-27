# brotli2scan - Check whether a website is affected by HTTP2Shell (CVE-2026-111497, Brotli)
FROM python:3.13-slim

LABEL org.opencontainers.image.title="brotli2scan" \
      org.opencontainers.image.description="Check whether a website is affected by HTTP2Shell (CVE-2026-111497, Brotli)" \
      org.opencontainers.image.licenses="GPL-3.0-only"

# unprivileged user, writable data volume (blocklist cache + audit log)
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin scanner \
 && mkdir -p /data && chown 10001:10001 /data

WORKDIR /app
COPY brotli2scan.py web.py ./
COPY static ./static

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PANIC_BIND=0.0.0.0 \
    PANIC_PORT=8089 \
    STATE_DIRECTORY=/data \
    PANIC_AUDIT_DIR=/data/audit \
    PANIC_RETENTION_DAYS=30

USER 10001
VOLUME ["/data"]
EXPOSE 8089

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8089/healthz', timeout=3)" || exit 1

ENTRYPOINT ["python3", "web.py"]
