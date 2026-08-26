# syntax=docker/dockerfile:1.5
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app \
    DATA_DIR=/app/data \
    MODEL_DIR=/app/models

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements_training.txt .
RUN pip install --no-cache-dir -r requirements_training.txt

# Copy application code
COPY training_2026/train_bccc_ddos.py .
COPY llm_ids/ ./llm_ids/

# Create directories for dataset and models
RUN mkdir -p ${DATA_DIR} ${MODEL_DIR}

# Default command (can be overridden at runtime)
CMD ["python", "train_bccc_ddos.py", "--data", "./data/merged_CSVs.csv", "--output-dir", "./bccc_ddos_model"]
