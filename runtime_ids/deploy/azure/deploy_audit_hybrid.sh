#!/usr/bin/env bash
# Deploy DECLARATIV al componentei audit hibrid v2.2 — O SINGURA cale canonica (imuabil + hardenat, fara drift).
#   MODE=image  (IMPLICIT, CANONIC): build+push imagine versionata (cod+model copt) + apply 11-audit-xgb.yaml
#                (hardenat: replicas=2, PDB, securityContext, anti-affinity, NetworkPolicy)
#   MODE=cfgmap (fallback dev, fara registry): ConfigMap via `kubectl apply --server-side` + 11-audit-xgb-cfgmap-fallback.yaml
#                (ACELASI pod-spec hardenat -> hardeningul NU difera intre cai)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
NS=runtime-ids; MODE="${MODE:-image}"; IMG="${IMG:-andreeagrigore/runtime-ids-audit:2.2}"   # default = tag-ul din manifestul canonic (evita drift build-vs-apply); manifestul pin-uieste @sha256
SVC="$ROOT/runtime_ids/service/audit_xgb_service.py"; MODELDIR="$ROOT/runtime_ids/models/audit_hybrid_v2"
kubectl get ns $NS >/dev/null 2>&1 || kubectl create ns $NS
if [ "$MODE" = "image" ]; then
  echo ">> [canonic] build $IMG"; docker build --platform linux/amd64 -f "$HERE/Dockerfile.audit" -t "$IMG" "$ROOT"
  echo ">> push $IMG";  docker push "$IMG"
  kubectl apply -f "$HERE/k8s/11-audit-xgb.yaml"
else
  echo ">> [fallback dev] ConfigMap server-side apply (evita limita de adnotare 262KB)"
  kubectl create configmap audit-xgb-code -n $NS \
    --from-file=audit_xgb_service.py="$SVC" \
    --from-file=classifier.json="$MODELDIR/classifier.json" \
    --from-file=pipeline_config.json="$MODELDIR/pipeline_config.json" \
    --dry-run=client -o yaml | kubectl apply --server-side --force-conflicts -f -
  kubectl apply -f "$HERE/k8s/11-audit-xgb-cfgmap-fallback.yaml"
fi
kubectl rollout status deploy ids-audit-xgb -n $NS --timeout=150s
echo ">> GATA deploy ($MODE). Ambele cai folosesc ACELASI pod-spec hardenat (zero drift)."
