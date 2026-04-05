# ══════════════════════════════════════════════
#  PhishGuard AI – Dockerfile
# ══════════════════════════════════════════════

FROM python:3.11-slim

# ── Metadata ───────────────────────────────
LABEL maintainer="PhishGuard AI"
LABEL description="AI-Powered Phishing Detection Tool"
LABEL version="1.0.0"

# ── Environment ────────────────────────────
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    PORT=5000

# ── Working directory ──────────────────────
WORKDIR /app

# ── Install dependencies ───────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Copy application ───────────────────────
COPY . .

# ── Create runtime directories ─────────────
RUN mkdir -p logs reports models

# ── Train the model on build ───────────────
RUN python -c "from model import train_model; train_model()" || echo "Model training deferred to runtime"

# ── Expose port ────────────────────────────
EXPOSE 5000

# ── Health check ───────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health')" || exit 1

# ── Entry point ────────────────────────────
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]
