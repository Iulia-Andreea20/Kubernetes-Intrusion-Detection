#!/usr/bin/env bash
# Kubernetes attack-emulation scenarios for the runtime-IDS dataset.
#
# Every scenario is RANDOMISED on each call - the number of API calls, their
# order, and their targets all vary - so a model cannot memorise a fixed
# script and must instead learn the attack *pattern*. Each scenario keeps its
# attacker intent and records a precise, labelled time window. Scenarios map
# to MITRE ATT&CK for Containers technique IDs.
set -uo pipefail

WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$WORKDIR/attacks/lib.sh"
LABELS="$WORKDIR/data/labels.jsonl"
CTX="${KUBE_CONTEXT:-kind-runtime-ids}"
K="kubectl --context $CTX"
NS=ids-demo
mkdir -p "$WORKDIR/data"

# record_label <scenario> <attack_type> <mitre> <start> <end>
record_label() {
  printf '{"scenario":"%s","attack_type":"%s","mitre":"%s","label":1,"start":"%s","end":"%s"}\n' \
    "$1" "$2" "$3" "$4" "$5" >> "$LABELS"
  echo "  [attack] $1 ($3)"
}

# Run a random-ordered subset of size $1 of the kubectl arg-strings $2..$n.
run_subset() {
  local n=$1; shift
  local sub=(); while IFS= read -r c; do sub+=("$c"); done < <(shuffle "$@")
  local c
  for c in "${sub[@]:0:$n}"; do
    $K $c >/dev/null 2>&1
    jitter
  done
}

# Scenario 1: cluster reconnaissance / discovery
scenario_recon() {
  local s; s=$(now)
  run_subset "$(ri 5 11)" \
    "get pods -A" "get secrets -A" "get configmaps -A" "get nodes -o wide" \
    "get serviceaccounts -A" "get clusterroles" "get rolebindings -A" \
    "get events -A" "auth can-i --list" "api-resources" "get namespaces" \
    "get deployments -A" "get services -A" "get clusterrolebindings"
  record_label "recon" "discovery" "T1613" "$s" "$(now)"
}

# Scenario 2: exec into a running container
scenario_exec_abuse() {
  local s; s=$(now)
  local pod
  pod=$($K -n "$NS" get pods -l app=target -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  if [ -n "${pod:-}" ]; then
    local pool=('id' 'cat /etc/passwd' 'env' 'uname -a' 'ps aux' 'ls -la /' \
                'whoami' 'cat /etc/shadow' 'hostname' 'cat /etc/hosts' 'mount')
    local sub=(); while IFS= read -r c; do sub+=("$c"); done < <(shuffle "${pool[@]}")
    local n; n=$(ri 2 7)
    local cmd
    for cmd in "${sub[@]:0:$n}"; do
      $K -n "$NS" exec "$pod" -- sh -c "$cmd" >/dev/null 2>&1
      jitter
    done
  fi
  record_label "exec_abuse" "container_exec" "T1609" "$s" "$(now)"
}

# Scenario 3: RBAC privilege escalation
scenario_rbac_escalation() {
  local s; s=$(now)
  local x="${1:-0}-$RANDOM"
  local verbs=('*' 'get,list,create,delete,patch' '*')
  local res=('*' '*' 'secrets,pods,deployments,nodes')
  local k=$(( RANDOM % 3 ))
  $K create clusterrole "ids-pwn-$x" --verb="${verbs[$k]}" --resource="${res[$k]}" 2>/dev/null
  $K create serviceaccount "attacker-$x" -n default 2>/dev/null
  $K create clusterrolebinding "ids-pwn-bind-$x" \
       --clusterrole="ids-pwn-$x" --serviceaccount="default:attacker-$x" 2>/dev/null
  if coin 50; then
    $K create role "ids-ns-$x" -n "$NS" --verb='*' --resource='*' 2>/dev/null
    $K create rolebinding "ids-ns-bind-$x" -n "$NS" \
         --role="ids-ns-$x" --serviceaccount="default:attacker-$x" 2>/dev/null
  fi
  record_label "rbac_escalation" "privilege_escalation" "T1078" "$s" "$(now)"
  $K delete clusterrolebinding "ids-pwn-bind-$x"    2>/dev/null
  $K delete clusterrole "ids-pwn-$x"                2>/dev/null
  $K delete rolebinding "ids-ns-bind-$x" -n "$NS"   2>/dev/null
  $K delete role "ids-ns-$x" -n "$NS"               2>/dev/null
  $K delete serviceaccount "attacker-$x" -n default 2>/dev/null
}

# Scenario 4: secret / credential theft
scenario_secret_access() {
  local s; s=$(now)
  local nspool=(default kube-system kube-public "$NS" kube-node-lease)
  local sub=(); while IFS= read -r c; do sub+=("$c"); done < <(shuffle "${nspool[@]}")
  local n; n=$(ri 2 5)
  local ns
  for ns in "${sub[@]:0:$n}"; do
    $K -n "$ns" get secrets -o yaml >/dev/null 2>&1
    coin 45 && $K -n "$ns" get configmaps -o yaml >/dev/null 2>&1
    jitter
  done
  coin 55 && $K get secrets --all-namespaces -o yaml >/dev/null 2>&1
  record_label "secret_access" "credential_theft" "T1552" "$s" "$(now)"
}

# Scenario 5: service-account token abuse
scenario_sa_token() {
  local s; s=$(now)
  local nspool=(kube-system default "$NS" kube-public)
  local sub=(); while IFS= read -r c; do sub+=("$c"); done < <(shuffle "${nspool[@]}")
  local n; n=$(ri 1 4)
  local ns
  for ns in "${sub[@]:0:$n}"; do
    $K create token default -n "$ns" --duration=1h >/dev/null 2>&1
    jitter
  done
  coin 50 && $K -n kube-system get serviceaccounts -o yaml >/dev/null 2>&1
  record_label "sa_token_abuse" "token_theft" "T1528" "$s" "$(now)"
}

# Scenario 6: deploy a privileged / host-mounting pod
scenario_malicious_pod() {
  local s; s=$(now)
  local x="${1:-0}-$RANDOM"
  local priv=false pid=false net=false hp=false
  case $(( RANDOM % 4 )) in
    0) priv=true; hp=true ;;
    1) pid=true;  net=true ;;
    2) priv=true ;;
    3) priv=true; pid=true; net=true; hp=true ;;
  esac
  {
    echo "apiVersion: v1"
    echo "kind: Pod"
    echo "metadata:"
    echo "  name: ids-escape-$x"
    echo "  namespace: default"
    echo "spec:"
    $pid && echo "  hostPID: true"
    $net && echo "  hostNetwork: true"
    echo "  containers:"
    echo "  - name: c"
    echo "    image: busybox:1.36"
    echo '    command: ["sh", "-c", "sleep 600"]'
    $priv && echo "    securityContext: {privileged: true}"
    $hp   && echo "    volumeMounts: [{name: host, mountPath: /host}]"
    $hp   && echo "  volumes: [{name: host, hostPath: {path: /}}]"
    true
  } | $K apply -f - >/dev/null 2>&1
  record_label "malicious_pod" "container_escape" "T1610" "$s" "$(now)"
  $K delete pod "ids-escape-$x" -n default --grace-period=0 --force 2>/dev/null
}

# Run a single scenario when executed directly:  ./attack_scenarios.sh scenario_recon
if [[ "${BASH_SOURCE[0]}" == "${0}" ]] && [ "${1:-}" != "" ]; then
  "$1" "${2:-}"
fi
