#!/usr/bin/env bash
# Generate benign Kubernetes activity for the runtime-IDS dataset.
#
# Both benign rounds are RANDOMISED on each call (random subset, order and
# parameters), so the benign class is as varied as the attack class - neither
# side is a fixed script the model could memorise.
#
#   benign_round       - ordinary workload operations
#   benign_admin_round - legitimate versions of the sensitive actions the
#                        attacks also perform (differ by scope/rate, not type)
#
# Benign events are NOT labelled: collect_audit.py treats every event outside
# an attack window in data/labels.jsonl as benign.
set -uo pipefail

WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$WORKDIR/attacks/lib.sh"
CTX="${KUBE_CONTEXT:-kind-runtime-ids}"
K="kubectl --context $CTX"
NS=ids-demo

deploy_target() {
  $K create namespace "$NS"                                            2>/dev/null
  $K -n "$NS" create deployment target --image=nginx:1.27 --replicas=2  2>/dev/null
  $K -n "$NS" expose deployment target --port=80                        2>/dev/null
  $K -n "$NS" create configmap app-config --from-literal=mode=prod      2>/dev/null
  $K -n "$NS" create secret generic app-secret --from-literal=token=demo 2>/dev/null
  $K -n "$NS" create role app-reader --verb=get,list,watch --resource=configmaps,pods 2>/dev/null
  $K -n "$NS" create rolebinding app-reader-bind \
       --role=app-reader --serviceaccount="$NS:default"                 2>/dev/null
  $K -n "$NS" rollout status deployment/target --timeout=120s           2>/dev/null
  true
}

# Ordinary cluster operations - a random subset, in random order.
benign_round() {
  local pool=("get pods" "get deployment target -o yaml" "describe deployment target" \
              "get events" "get configmaps" "get replicasets" "get services" \
              "get pods -o wide" "get endpoints" "get deployments")
  local sub=(); while IFS= read -r c; do sub+=("$c"); done < <(shuffle "${pool[@]}")
  local n; n=$(ri 4 8)
  local c
  for c in "${sub[@]:0:$n}"; do
    $K -n "$NS" $c >/dev/null 2>&1
    jitter
  done
  coin 50 && $K -n "$NS" logs -l app=target --tail="$(ri 5 30)" >/dev/null 2>&1
  coin 60 && $K -n "$NS" scale deployment target --replicas="$(ri 2 4)" >/dev/null 2>&1
  coin 40 && $K get namespaces >/dev/null 2>&1
  true
}

# Legitimate versions of the sensitive actions - each fires with some
# probability, with varied parameters.
benign_admin_round() {
  local x="$RANDOM"
  local pod
  pod=$($K -n "$NS" get pods -l app=target -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  if [ -n "${pod:-}" ] && coin 70; then
    local bcmds=('nginx -v' 'ls /etc/nginx' 'cat /etc/nginx/nginx.conf' 'date' 'df -h')
    local sub=(); while IFS= read -r c; do sub+=("$c"); done < <(shuffle "${bcmds[@]}")
    local cmd
    for cmd in "${sub[@]:0:$(ri 1 2)}"; do
      $K -n "$NS" exec "$pod" -- sh -c "$cmd" >/dev/null 2>&1
    done
  fi
  coin 75 && $K -n "$NS" get configmap app-config >/dev/null 2>&1
  coin 65 && $K -n "$NS" get secret app-secret    >/dev/null 2>&1
  coin 50 && $K -n "$NS" get secrets              >/dev/null 2>&1
  if coin 60; then
    $K -n "$NS" create role "tmp-reader-$x" --verb=get,list --resource=configmaps >/dev/null 2>&1
    $K -n "$NS" create rolebinding "tmp-reader-bind-$x" \
         --role="tmp-reader-$x" --serviceaccount="$NS:default"           >/dev/null 2>&1
    $K -n "$NS" delete rolebinding "tmp-reader-bind-$x"                   >/dev/null 2>&1
    $K -n "$NS" delete role "tmp-reader-$x"                               >/dev/null 2>&1
  fi
  if coin 55; then
    $K create clusterrole "tmp-monitor-$x" --verb=get,list,watch --resource=pods,nodes >/dev/null 2>&1
    $K create clusterrolebinding "tmp-monitor-bind-$x" \
         --clusterrole="tmp-monitor-$x" --serviceaccount="$NS:default"   >/dev/null 2>&1
    $K delete clusterrolebinding "tmp-monitor-bind-$x"                    >/dev/null 2>&1
    $K delete clusterrole "tmp-monitor-$x"                                >/dev/null 2>&1
  fi
  coin 70 && $K -n "$NS" create token default --duration=1h >/dev/null 2>&1
  if coin 60; then
    $K -n default run "benign-job-$x" --image=busybox:1.36 --restart=Never \
         --command -- sh -c 'sleep 300'                                  >/dev/null 2>&1
    $K -n default delete pod "benign-job-$x" --grace-period=0 --force     >/dev/null 2>&1
  fi
  true
}

case "${1:-all}" in
  deploy) deploy_target ;;
  round)  benign_round ;;
  admin)  benign_admin_round ;;
  all)
    deploy_target
    for _ in $(seq 1 "${2:-3}"); do benign_round; benign_admin_round; done
    ;;
esac
