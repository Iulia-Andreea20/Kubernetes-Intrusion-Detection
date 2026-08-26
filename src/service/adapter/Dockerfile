# The Log Analytics adapter. Build from the repository root:
#   docker build -f src/service/adapter/Dockerfile -t ids-audit-adapter:2.3 .
FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY src/service/adapter/requirements.txt /app/req.txt
RUN pip install --no-cache-dir -r /app/req.txt
COPY src/service/adapter/audit_loganalytics_adapter.py /app/adapter.py
CMD ["python", "adapter.py"]
