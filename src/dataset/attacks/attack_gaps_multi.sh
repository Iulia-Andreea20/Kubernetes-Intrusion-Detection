#!/usr/bin/env bash
# Collect several varied episodes per class (lateral, impact, evasion) under distinct identities,
# so the evaluation can split train/held-out on identity and ask whether the classifier generalises
# to a new actor rather than memorising the one it saw.
#
# Everything destructive is confined to the scratch namespaces lab-victim and decoy.
OUT="$(cd "$(dirname "$0")/../reference" && pwd)"; SF="$OUT/sessions.txt"; mkdir -p "$OUT"; touch "$SF"
VNS=lab-victim
nowZ(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
kubectl create namespace $VNS >/dev/null 2>&1 || true
mkkc(){ kubectl create sa "$1" -n default >/dev/null 2>&1||true
  kubectl create clusterrolebinding "rt-$1" --clusterrole=cluster-admin --serviceaccount=default:"$1" >/dev/null 2>&1||true
  local T; T=$(kubectl create token "$1" -n default --duration=3h 2>/dev/null); local KC=/tmp/kc-$1
  kubectl config --kubeconfig="$KC" set-cluster c --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
  kubectl config --kubeconfig="$KC" set-credentials u --token="$T" >/dev/null
  kubectl config --kubeconfig="$KC" set-context c --cluster=c --user=u >/dev/null
  kubectl config --kubeconfig="$KC" use-context c >/dev/null; echo "$KC"; }
populate(){ for i in $(seq 1 14); do kubectl create configmap dcm-$1-$i --from-literal=k=v -n $VNS >/dev/null 2>&1; done
  for i in $(seq 1 10); do kubectl create secret generic dsec-$1-$i --from-literal=p=x -n $VNS >/dev/null 2>&1; done
  kubectl create deployment dapp-$1 --image=nginx -n $VNS >/dev/null 2>&1; }
SESN(){ N=$(grep -cE "SESSION [0-9]+ START" "$SF"); echo $((N+1)); }
CREATED=""

# lateral movement: three different identities
SAS="system:serviceaccount:kube-system:namespace-controller system:serviceaccount:kube-system:generic-garbage-collector system:serviceaccount:kube-system:replicaset-controller system:serviceaccount:kube-system:deployment-controller system:admin system:serviceaccount:cert-manager:cert-manager"
li=0
for variant in pure mixed broad; do
  li=$((li+1)); SA=adversary-lat-$li; KC=$(mkkc $SA); CREATED="$CREATED $SA"
  KAS(){ kubectl --kubeconfig "$KC" --as="$1" "${@:2}" >/dev/null 2>&1 || true; }
  S=$(SESN); echo "  S$S LATERAL/$variant ($SA)"; echo "SESSION $S START $(nowZ)" >> "$SF"
  k=0
  for as in $SAS; do
    k=$((k+1))
    case $variant in
      pure)  KAS "$as" get pods -A; KAS "$as" get deployments -A;;
      mixed) KAS "$as" get pods -A; [ $((k%2)) -eq 0 ] && KAS "$as" get secrets -n kube-system;;
      broad) KAS "$as" get pods -A; KAS "$as" get services -A; KAS "$as" get configmaps -A;;
    esac
  done
  for as in $SAS; do KAS "$as" get namespaces; KAS "$as" get nodes; done
  echo "SESSION $S END $(nowZ)" >> "$SF"
done

# impact: three identities, deletion and hijack
ii=0
for variant in cm-sec deploy-svc bulk; do
  ii=$((ii+1)); SA=adversary-imp-$ii; KC=$(mkkc $SA); CREATED="$CREATED $SA"; populate $SA
  KI(){ kubectl --kubeconfig "$KC" "$@" >/dev/null 2>&1 || true; }
  S=$(SESN); echo "  S$S IMPACT/$variant ($SA)"; echo "SESSION $S START $(nowZ)" >> "$SF"
  case $variant in
    cm-sec)    for i in $(seq 1 14); do KI delete configmap dcm-$SA-$i -n $VNS; done
               for i in $(seq 1 10); do KI delete secret dsec-$SA-$i -n $VNS; done;;
    deploy-svc) KI create deployment miner-$SA --image=nginx --replicas=6 -n $VNS; KI delete deployment dapp-$SA -n $VNS
               for i in $(seq 1 12); do KI delete configmap dcm-$SA-$i -n $VNS; done; KI delete deployment miner-$SA -n $VNS;;
    bulk)      KI create deployment xmr-$SA --image=nginx --replicas=8 -n $VNS
               for i in $(seq 1 14); do KI delete configmap dcm-$SA-$i -n $VNS; done
               for i in $(seq 1 10); do KI delete secret dsec-$SA-$i -n $VNS; done; KI delete deployment xmr-$SA dapp-$SA -n $VNS;;
  esac
  echo "SESSION $S END $(nowZ)" >> "$SF"
done

# evasion: three identities, deleting defences
ei=0
for variant in np-evt wh-crb mixed; do
  ei=$((ei+1)); SA=adversary-eva-$ei; KC=$(mkkc $SA); CREATED="$CREATED $SA"
  # defensive decoys, created as admin
  for i in $(seq 1 6); do printf 'apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: np-%s-%s, namespace: %s}\nspec: {podSelector: {}, policyTypes: [Ingress]}\n' "$SA" "$i" "$VNS" | kubectl apply -f - >/dev/null 2>&1||true; done
  for i in 1 2; do printf 'apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingWebhookConfiguration\nmetadata: {name: wh-%s-%s}\nwebhooks:\n- name: w%s.example.com\n  failurePolicy: Ignore\n  sideEffects: None\n  admissionReviewVersions: [v1]\n  namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: %s}}\n  rules: [{apiGroups: [""], apiVersions: [v1], operations: [CREATE], resources: [configmaps]}]\n  clientConfig: {url: "https://127.0.0.1:1/x"}\n' "$SA" "$i" "$i" "$VNS" | kubectl apply -f - >/dev/null 2>&1||true; done
  KE(){ kubectl --kubeconfig "$KC" "$@" >/dev/null 2>&1 || true; }
  S=$(SESN); echo "  S$S EVASION/$variant ($SA)"; echo "SESSION $S START $(nowZ)" >> "$SF"
  KE delete events --all -n $VNS
  case $variant in
    np-evt) for i in $(seq 1 6); do KE delete networkpolicy np-$SA-$i -n $VNS; done; KE delete events --all -n $VNS; KE get events -n $VNS;;
    wh-crb) KE delete validatingwebhookconfiguration wh-$SA-1 wh-$SA-2; KE create clusterrolebinding ev-$SA --clusterrole=cluster-admin --serviceaccount=$VNS:default; KE delete clusterrolebinding ev-$SA; for i in $(seq 1 6); do KE delete networkpolicy np-$SA-$i -n $VNS; done;;
    mixed)  for i in $(seq 1 6); do KE delete networkpolicy np-$SA-$i -n $VNS; done; KE delete validatingwebhookconfiguration wh-$SA-1 wh-$SA-2; KE delete pod --all -n $VNS; KE delete clusterrolebinding rt-adversary-lat-1;;
  esac
  echo "SESSION $S END $(nowZ)" >> "$SF"
done

echo ">> cleanup..."
for s in $CREATED; do kubectl delete clusterrolebinding rt-$s >/dev/null 2>&1||true; kubectl delete sa $s -n default >/dev/null 2>&1||true; done
kubectl delete validatingwebhookconfiguration -l '' >/dev/null 2>&1||true
kubectl get validatingwebhookconfiguration -o name 2>/dev/null | grep -E 'wh-adversary' | xargs -r kubectl delete >/dev/null 2>&1||true
kubectl delete namespace $VNS >/dev/null 2>&1||true
echo ">> done. new sessions:"; tail -9 "$SF"