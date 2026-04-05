FROM python:3.11-slim

LABEL maintainer="PQC-Analyzer"
LABEL description="Post-Quantum Cryptography Analyzer with AI Optimization"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .
RUN pip install --no-cache-dir -e .

# Create output directories
RUN mkdir -p outputs logs

EXPOSE 8000

ENTRYPOINT ["uvicorn", "pqc_analyzer.api.server:app"]
CMD ["--host", "0.0.0.0", "--port", "8000"]
