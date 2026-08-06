FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    NTSHIELD_HOST=0.0.0.0 \
    NTSHIELD_PORT=8088 \
    NTSHIELD_DATABASE_PATH=/data/ntshield-brain.db \
    NTSHIELD_PLAYBOOK_DIR=/app/playbooks

WORKDIR /app

COPY pyproject.toml README.md ./
COPY app ./app
COPY playbooks ./playbooks

RUN pip install --upgrade pip && pip install . && \
    useradd --system --uid 10001 --create-home ntshield && \
    mkdir -p /data && chown -R ntshield:ntshield /data /app

USER ntshield
EXPOSE 8088

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8088/health', timeout=3)" || exit 1

CMD ["uvicorn", "app.main_v2:app", "--host", "0.0.0.0", "--port", "8088", "--workers", "1"]
