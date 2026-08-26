# Kubernetes Deployment Guide for LLM-based IDS

This directory contains Kubernetes manifests for deploying the LLM-based Intrusion Detection System.

## Prerequisites

1. Kubernetes cluster (v1.20+)
2. kubectl configured to access your cluster
3. PersistentVolume provisioner (for model storage)
4. Trained model files (see training guide)

## Deployment Steps

### 1. Create Namespace

```bash
kubectl apply -f namespace.yaml
```

### 2. Create ConfigMap

```bash
kubectl apply -f configmap.yaml
```

### 3. Create PersistentVolumeClaim for Model Storage

```bash
kubectl apply -f pvc.yaml
```

**Note**: You'll need to upload your trained model to the PVC. You can do this by:
- Creating a Job that copies the model files
- Using kubectl cp to copy files to a pod
- Using a storage provisioner that supports ReadWriteMany

### 4. Build and Push Docker Image

```bash
cd ../llm_ids
docker build -t llm-ids-inference:latest .
docker tag llm-ids-inference:latest <your-registry>/llm-ids-inference:latest
docker push <your-registry>/llm-ids-inference:latest
```

Update the image in `deployment.yaml` if using a registry.

### 5. Deploy the Inference Service

```bash
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```

### 6. (Optional) Deploy HPA for Auto-scaling

```bash
kubectl apply -f hpa.yaml
```

### 7. (Optional) Apply NetworkPolicy

```bash
kubectl apply -f networkpolicy.yaml
```

## Verification

### Check Deployment Status

```bash
kubectl get pods -n ids-system
kubectl get svc -n ids-system
```

### Test the Service

```bash
# Port forward to access the service
kubectl port-forward -n ids-system svc/llm-ids-inference 8000:8000

# Test health endpoint
curl http://localhost:8000/health

# Test prediction endpoint
curl -X POST http://localhost:8000/predict/network \
  -H "Content-Type: application/json" \
  -d '{
    "duration_s": 2.5,
    "tot_fwd_pkts": 10,
    "tot_bwd_pkts": 8,
    "tot_bytes": 2048,
    "src_ip": "10.0.1.5",
    "dst_ip": "10.0.1.10",
    "src_port": 54321,
    "dst_port": 443,
    "protocol": 6,
    "src_is_pod": true,
    "dst_is_pod": true
  }'
```

## Configuration

Edit `configmap.yaml` to adjust:
- Classification threshold
- Model settings
- Data collection settings
- Alert settings

## Monitoring

### View Logs

```bash
kubectl logs -n ids-system -l app=llm-ids-inference --tail=100
```

### Check Resource Usage

```bash
kubectl top pods -n ids-system
```

### View HPA Status

```bash
kubectl get hpa -n ids-system
```

## Troubleshooting

### Pod Not Starting

1. Check pod logs: `kubectl logs -n ids-system <pod-name>`
2. Check events: `kubectl describe pod -n ids-system <pod-name>`
3. Verify model files are in PVC: `kubectl exec -n ids-system <pod-name> -- ls -la /app/models`

### Model Not Loading

1. Verify model path in ConfigMap
2. Check that model files exist in PVC
3. Check model format (should be HuggingFace format)

### High Memory Usage

1. Reduce batch size in ConfigMap
2. Use a smaller model (e.g., DistilBERT instead of BERT)
3. Increase memory limits in deployment.yaml

## Scaling

The HPA will automatically scale based on CPU and memory usage. You can also manually scale:

```bash
kubectl scale deployment llm-ids-inference -n ids-system --replicas=5
```

## Security Considerations

1. **NetworkPolicy**: Restricts pod communication (already applied)
2. **RBAC**: Consider creating a ServiceAccount with minimal permissions
3. **Secrets**: Store sensitive configuration in Secrets, not ConfigMaps
4. **TLS**: Consider adding TLS termination for production

## Next Steps

1. Set up data collection pipeline (see `data_collector.py`)
2. Configure alerting (webhook, Slack, etc.)
3. Set up monitoring dashboards (Prometheus, Grafana)
4. Implement log aggregation (ELK, Loki)
