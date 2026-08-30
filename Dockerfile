FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ADP_DB=/data/adp.db

WORKDIR /app
COPY pyproject.toml README.md ./
COPY adp ./adp
COPY server ./server

RUN pip install --no-cache-dir . \
 && useradd --system --uid 10001 adp \
 && mkdir -p /data && chown adp:adp /data

USER adp
EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health').read()"

# One worker on purpose: the budget ledger and audit chain share a single
# SQLite connection. Scale out behind a load balancer with a shared ADP_DB.
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
