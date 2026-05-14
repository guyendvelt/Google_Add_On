# FastAPI backend — Malicious Email Scorer
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install deps first so the cache layer is reused when only source changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source.
COPY main.py schemas.py database.py models.py heuristics.py \
     virustotal.py stats.py ./

EXPOSE 8000

# On startup: ensure the Postgres schema exists (create_all is idempotent),
# then start uvicorn. The DB service in docker-compose has a healthcheck so
# this only fires once Postgres is accepting connections.
CMD ["sh", "-c", "python -c 'from database import Base, engine; import models; Base.metadata.create_all(bind=engine)' && uvicorn main:app --host 0.0.0.0 --port 8000"]
