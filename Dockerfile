FROM python:3.11-slim

# Install system packages + CA certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy application code
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    httpx \
    feedparser \
    lxml \
    defusedxml \
    requests \
    certifi \
    idna \
    charset-normalizer \
    python-dotenv \
    beautifulsoup4

# Expose your app port
EXPOSE 8123

# Start FastAPI
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8123"]
