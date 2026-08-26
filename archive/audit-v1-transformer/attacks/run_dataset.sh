#!/usr/bin/env bash
# Generate a labelled runtime-IDS dataset: loop benign activity interleaved
# with attack scenarios, all captured by the API-server audit log.
#
# Round count is configurable (more rounds = more attack examples):
#   ROUNDS=30 ./attacks/run_dataset.sh
#
# Benign and attack phases never overlap, so time-window labelling is clean.
set -uo pipefail

WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$WORKDIR"
source attacks/attack_scenarios.sh

ROUNDS="${ROUNDS:-12}"

mkdir -p data
: > data/labels.jsonl
now > data/run_start          # collector ignores audit events before this mark
echo "[*] run_start : $(cat data/run_start)"
echo "[*] rounds    : $ROUNDS"

echo "[*] Deploying target workload + warm-up benign activity"
./attacks/benign_workload.sh deploy
./attacks/benign_workload.sh all 3

ATTACKS=(scenario_recon scenario_exec_abuse scenario_rbac_escalation
         scenario_secret_access scenario_sa_token scenario_malicious_pod)

for r in $(seq 1 "$ROUNDS"); do
  echo "[*] Round $r/$ROUNDS"
  ./attacks/benign_workload.sh round            # ordinary benign activity
  ./attacks/benign_workload.sh admin            # benign sensitive actions
  # shuffle the attack order each round so cross-scenario context varies
  ordered=(); while IFS= read -r sc; do ordered+=("$sc"); done < <(shuffle "${ATTACKS[@]}")
  for sc in "${ordered[@]}"; do
    "$sc" "$r"
  done
  ./attacks/benign_workload.sh round
  ./attacks/benign_workload.sh admin
done

echo "[*] Final benign activity"
./attacks/benign_workload.sh all 3

echo "[*] Done."
echo "    attack windows : $(wc -l < data/labels.jsonl)"
echo "    audit events   : $(wc -l < audit-logs/audit.log 2>/dev/null || echo 0)"
echo
echo "Next: python3 collect/collect_audit.py"
