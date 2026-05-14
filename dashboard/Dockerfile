# Streamlit admin dashboard — Malicious Email Scorer
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The .streamlit/config.toml lives at /app/.streamlit and is picked up
# automatically by Streamlit at startup (dark theme + headless mode).
COPY .streamlit ./.streamlit
COPY app.py .

EXPOSE 8501

# --server.address=0.0.0.0 makes the app reachable from the host port
# mapping; the default 127.0.0.1 would only listen inside the container.
CMD ["streamlit", "run", "app.py", \
     "--server.address=0.0.0.0", \
     "--server.port=8501", \
     "--server.headless=true"]
