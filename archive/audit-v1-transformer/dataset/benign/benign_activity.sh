#!/bin/bash
# Activitate BENIGNĂ ca 'alice' (rol view): operațiuni normale de citire, repetate.
# Produce tokeni get/list pe resurse uzuale -> trafic de operator normal.
set -uo pipefail
KC="${KC:-/tmp/ids_collect/kubeconfig-alice}"
K="kubectl --kubeconfig $KC"
ROUNDS="${ROUNDS:-12}"
echo "BENIGN_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
for r in $(seq 1 "$ROUNDS"); do
  $K get pods -A            >/dev/null 2>&1
  $K get services -A        >/dev/null 2>&1
  $K get deployments -A     >/dev/null 2>&1
  $K get nodes              >/dev/null 2>&1
  $K get configmaps -A      >/dev/null 2>&1
  $K get namespaces         >/dev/null 2>&1
  $K get events -A          >/dev/null 2>&1
  $K get pods -n kube-system >/dev/null 2>&1
  $K get replicasets -A     >/dev/null 2>&1
  $K get endpoints -A       >/dev/null 2>&1
  echo "   runda benignă $r/$ROUNDS"
  sleep 1
done
echo "BENIGN_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
