#!/bin/bash
# SCALĂ INDUSTRIALĂ — N sesiuni secvențiale. Programare DETERMINISTĂ a profilurilor de atac (garantează
# stratificarea train/test: fiecare profil în ambele jumătăți, recon >=4 episoade test) + conținut
# RANDOMIZAT pe sesiune (seed=index, reproductibil). 4 profiluri atac:
#   victim-sa (stolen-token, forbid mare) | adversary-external (valid-abuse, forbid mic) |
#   adversary-insider (low-and-slow) | recon-sa (enumerare permisiuni = grilă can-i).
# Injectare BENIGN can-i la 4 niveluri de volum care SE SUPRAPUN cu reconul (label 0) ca să forțeze
# modelul pe burst/comportament, NU pe simpla prezență a selfsubjectaccessreviews (anti-artefact).
# Reset de stare între sesiuni. SA-urile recon-sa/compliance-scanner-sa sunt create de setup_actors.sh.
set -uo pipefail
W=/tmp/ids_collect; HERE="$(cd "$(dirname "$0")" && pwd)"; OUT="${OUT:-$HERE/../reference}"
K(){ kubectl --kubeconfig "$W/kubeconfig-$1" "${@:2}" >/dev/null 2>&1 || true; }   # actor pe certificat
N="${N:-24}"; SF="$OUT/sessions.txt"; : > "$SF"
KI="$W/kubeconfig-adversary-insider"; KE="$W/kubeconfig-adversary-external"
SERVER="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"

# token kubeconfig pt un SA (token proaspăt, valabil tot run-ul < 3h)
mk_kc(){ local sa=$1; local kc="$W/kc-$sa"; local t; t=$(kubectl create token "$sa" -n default --duration=3h 2>/dev/null)
  kubectl config --kubeconfig="$kc" set-cluster a --server="$SERVER" --insecure-skip-tls-verify=true >/dev/null
  kubectl config --kubeconfig="$kc" set-credentials u --token="$t" >/dev/null
  kubectl config --kubeconfig="$kc" set-context a --cluster=a --user=u >/dev/null
  kubectl config --kubeconfig="$kc" use-context a >/dev/null; echo "$kc"; }
RC=$(mk_kc recon-sa); CC=$(mk_kc compliance-scanner-sa)
RR(){ kubectl --kubeconfig "$RC" "$@" >/dev/null 2>&1 || true; }   # recon-sa (ATAC)
CR(){ kubectl --kubeconfig "$CC" "$@" >/dev/null 2>&1 || true; }   # compliance-scanner-sa (BENIGN)

VERBS=(get list watch create delete update patch)
RES=(pods secrets services deployments configmaps nodes clusterroles rolebindings serviceaccounts jobs ingresses daemonsets statefulsets cronjobs persistentvolumeclaims networkpolicies)
RV(){ echo "${VERBS[$((RANDOM%${#VERBS[@]}))]}"; }   # verb random
RS(){ echo "${RES[$((RANDOM%${#RES[@]}))]}"; }       # resursă random
CUT=$(( N*7/10 ))

for s in $(seq 1 "$N"); do
  RANDOM=$s   # seed reproductibil pe sesiune -> conținut variat dar determinist
  echo "  === SESIUNE $s/$N ==="
  echo "SESSION $s START $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$SF"

  # BENIGN de fundal (actori + platform-admin)
  for r in $(seq 1 4); do
    K sre-oncall get pods -A; K sre-oncall get events -A; K sre-oncall get nodes
    K devops-pipeline create deployment d-$s-$r --image=nginx -n default; K devops-pipeline get pods -n default
    K security-auditor get clusterroles; K security-auditor get roles -A; K security-auditor get clusterrolebindings
    K platform-admin create serviceaccount p-$s-$r -n default; K platform-admin create clusterrolebinding pb-$s-$r --clusterrole=view --serviceaccount=default:p-$s-$r; K platform-admin get secrets -n default
  done
  # BENIGN can-i #1: check-then-act (volum 1-2, burst=1, urmat de ACȚIUNE reală) = pattern-ul benign dominant
  for r in $(seq 1 3); do
    K devops-pipeline auth can-i create deployments -n default; K devops-pipeline create deployment cta-$s-$r --image=nginx -n default
    K platform-engineer auth can-i create services -n default; K platform-engineer get services -n default
  done
  # BENIGN can-i #2: CI preflight batch (ci-deployer: 6-12 can-i, apoi deploy real) -> SE SUPRAPUNE cu reconul în volum
  npf=$(( 6 + RANDOM % 7 ))
  for i in $(seq 1 $npf); do K ci-deployer auth can-i "$(RV)" "$(RS)" -n default; done
  K ci-deployer create deployment ci-$s --image=nginx -n default; K ci-deployer get pods -n default
  # BENIGN can-i #3: dashboard page-load (sre-oncall: burst CONTIGUU 8-15 can-i, FĂRĂ acțiune) = Lens/Headlamp
  nd=$(( 8 + RANDOM % 8 ))
  for i in $(seq 1 $nd); do K sre-oncall auth can-i "$(RV)" "$(RS)"; done
  # BENIGN can-i #4: compliance scan (compliance-scanner-sa = SA la volum MARE 15-25, dar INTERCALAT cu citiri reale
  #                  -> rupe rularea contiguă: n_selfreview mare DAR burst_max mic. Cel mai greu FP benign.)
  for round in $(seq 1 3); do
    nc=$(( 5 + RANDOM % 4 ))
    for i in $(seq 1 $nc); do CR auth can-i "$(RV)" "$(RS)" -n default; done
    CR get pods -n default; CR get configmaps -n default; CR get roles -n default   # citiri reale -> rup burst-ul
  done

  # ATAC: programare deterministă (stratificare) + conținut randomizat
  # victim-sa (stolen-token, forbid mare): sesiuni IMPARE  [train odd<=15, test {17,19,21,23}]
  if (( s % 2 == 1 )); then ROUNDS=$(( 2 + RANDOM % 3 )) bash "$HERE/attack_realistic.sh" >/dev/null 2>&1 || true; fi

  # adversary-external (valid-abuse, forbid mic): sesiuni PARE  [train even<=16, test {18,20,22,24}]
  if (( s % 2 == 0 )); then
    nep=$(( 2 + RANDOM % 2 ))
    for ep in $(seq 1 $nep); do
      K adversary-external get secrets -A; K adversary-external get serviceaccounts -A; K adversary-external get clusterroles; K adversary-external get pods -A -o wide
      for sx in $(kubectl --kubeconfig $KE get secrets -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' 2>/dev/null|head -5); do K adversary-external get secret "${sx#*/}" -n "${sx%/*}" -o yaml; done
      K adversary-external run x-$s-$ep --image=alpine --restart=Never -- sleep 600
      kubectl --kubeconfig $KE wait --for=condition=ready pod/x-$s-$ep --timeout=20s >/dev/null 2>&1||true
      K adversary-external exec x-$s-$ep -- sh -c "id; cat /var/run/secrets/kubernetes.io/serviceaccount/token"
      K adversary-external create clusterrolebinding xb-$s-$ep --clusterrole=cluster-admin --serviceaccount=default:default
      K adversary-external delete pod x-$s-$ep --force --grace-period=0
    done
  fi

  # recon-sa (enumerare permisiuni = grilă can-i CONTIGUĂ): sesiuni PARE  [train even<=16, test {18,20,22,24} -> 4 ep]
  # 25-50 can-i pe (verb,resursă) random; cu prob ~0.4 -> DILUAT (citiri intercalate = recon low-and-slow, uneori ratat)
  if (( s % 2 == 0 )); then
    ncani=$(( 25 + RANDOM % 26 )); dilute=$(( RANDOM % 10 < 4 ))
    for i in $(seq 1 $ncani); do
      RR auth can-i "$(RV)" "$(RS)"
      if (( dilute )) && (( i % 3 == 0 )); then RR get pods -n default; fi
    done
  fi

  # adversary-insider (low-and-slow): sesiuni cu s%3 != 0  [acoperă ambele jumătăți]
  if (( s % 3 != 0 )); then
    dil=$(( 6 + RANDOM % 7 ))
    for r in $(seq 1 $dil); do
      K adversary-insider get pods -n default; K adversary-insider get services -A; K adversary-insider get configmaps -n default
      K adversary-insider get deployments -A; K adversary-insider get events -A; K adversary-insider get namespaces
      case $((r % 3)) in
        0) sx=$(kubectl --kubeconfig $KI get secrets -n kube-system -o jsonpath='{.items[0].metadata.name}' 2>/dev/null||true); [ -n "$sx" ] && K adversary-insider get secret "$sx" -n kube-system -o yaml ;;
        1) K adversary-insider create serviceaccount sb-$s-$r -n default ;;
        2) K adversary-insider get serviceaccounts -n kube-system ;;
      esac
    done
  fi

  echo "SESSION $s END $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$SF"
  # RESET stare (NU ștergem recon-sa/compliance-scanner-sa = actori persistenți)
  for r in $(seq 1 4); do kubectl delete clusterrolebinding pb-$s-$r >/dev/null 2>&1; kubectl delete sa p-$s-$r sb-$s-$r -n default >/dev/null 2>&1; kubectl delete deploy d-$s-$r cta-$s-$r -n default >/dev/null 2>&1; done
  kubectl delete deploy ci-$s -n default >/dev/null 2>&1
  for ep in $(seq 1 3); do kubectl delete clusterrolebinding xb-$s-$ep >/dev/null 2>&1; done
  echo "   sesiune $s gata"
done
echo "GATA scale ($N sesiuni). cut train/test la sesiunea $CUT (train 1-$CUT, test $((CUT+1))-$N)."; cat "$SF"
