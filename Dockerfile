# FS-2605 — Guarded AI Financial Assistant
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/
COPY bench/ bench/

# Unprivileged user
RUN useradd -m runner && chown -R runner /app
USER runner

ENV DB_PATH=/tmp/ledger.db
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
