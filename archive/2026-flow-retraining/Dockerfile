# syntax=docker/dockerfile:1.5
FROM pytorch/pytorch:2.2.2-cuda12.1-cudnn8-runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-container.txt .
RUN pip install --no-cache-dir -r requirements-container.txt

COPY train_distilbert.py .
COPY test_model.py .
COPY merge_csvs.py .
COPY create_holdout_split.py .
COPY tabular_data.py .
COPY train_xgboost.py .
COPY train_lightgbm.py .
COPY threshold_sweep.py .
COPY cross_dataset_eval.py .
COPY benchmark_models.py .
COPY itu_to_bccc.py .
COPY llm_ids/ ./llm_ids/

RUN mkdir -p /app/data /app/models

CMD ["python", "train_distilbert.py", "--data", "/app/data/merged_CSVs.csv", "--output-dir", "/app/models/bccc_ddos_model"]
