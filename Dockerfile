# ── Builder stage ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime stage ──────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="Secure Research Portal"
LABEL description="Production Flask API with JWT, MongoDB, Redis, and S3 storage"

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

# Do NOT copy .env — inject via docker-compose / Kubernetes secrets
RUN rm -f .env

# Ensure uploads dir exists (if any local file ops needed)
RUN mkdir -p /app/uploads && chown -R appuser:appuser /app

USER appuser

EXPOSE 5000

# Health check — polls /health every 30s
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"

# Production: run with gunicorn, 4 workers
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "4", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:create_app('production')"]
