#!/usr/bin/env bash
# Deploy the audit detector. Two paths, both landing on the same hardened pod spec so that
# whichever you use, the running configuration is identical.
#   MODE=image   build and push a versioned image with code and model baked in (default)
#   MODE=cfgmap  no registry needed: mount code and model from a ConfigMap instead
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
NS=runtime-ids; MODE="${MODE:-image}"; IMG="${IMG:-andreeagrigore/runtime-ids-audit:2.2}"   # matches the tag in the manifest; the manifest itself pins @sha256
SVC="$ROOT/src/service/audit/audit_xgb_service.py"; MODELDIR="$ROOT/src/model/artifacts/audit-xgb-v2.6"
kubectl get ns $NS >/dev/null 2>&1 || kubectl create ns $NS
if [ "$MODE" = "image" ]; then
  echo ">> build $IMG"; docker build --platform linux/amd64 -f "$HERE/../images/Dockerfile.audit" -t "$IMG" "$ROOT"
  echo ">> push $IMG";  docker push "$IMG"
  kubectl apply -f "$HERE/../k8s/11-audit-xgb.yaml"
else
  # Server-side apply: the model is too big for the 262KB client-side annotation limit.
  echo ">> ConfigMap (server-side apply)"
  kubectl create configmap audit-xgb-code -n $NS \
    --from-file=audit_xgb_service.py="$SVC" \
    --from-file=classifier.json="$MODELDIR/classifier.json" \
    --from-file=pipeline_config.json="$MODELDIR/pipeline_config.json" \
    --dry-run=client -o yaml | kubectl apply --server-side --force-conflicts -f -
  kubectl apply -f "$HERE/../k8s/11-audit-xgb-cfgmap-fallback.yaml"
fi
kubectl rollout status deploy ids-audit-xgb -n $NS --timeout=150s
echo ">> deployed ($MODE)"
