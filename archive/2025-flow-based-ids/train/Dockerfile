FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ART_DIR=/app/artifacts \
    TRAIN_DIR=/app/training \
    THRESHOLD=0.90

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy code
COPY ids_pipeline.py server.py entrypoint.sh ./
RUN chmod +x entrypoint.sh

#  Create and fix perms for dirs
RUN mkdir -p /app/training /app/artifacts && \
    chmod -R 777 /app && \
    chmod -R 777 /app/training /app/artifacts

# Expose API port
EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]
CMD ["serve"]