# Demo-uri IDS Kubernetes

## 🟢 CANONIC — Demo „from zero" pe AKS managed (sistemul ACTUAL v2.2)

```bash
./demo/run_demo_aks.sh            # fără argument: --status + --train (sigur, științific)
./demo/run_demo_aks.sh --deploy   # IDS v2.2 (audit hibrid digest-pinned) + Prometheus + Grafana + adapter LIVE
./demo/run_demo_aks.sh --train    # reproduce tabelul Wilson din ref_v2_all.csv (DETERMINIST)
./demo/run_demo_aks.sh --attack   # atac real -> adapter Log Analytics -> /predict/raw -> alertă (Grafana)
./demo/run_demo_aks.sh --provision  # [~10 min] ridică AKS+ACR+Log Analytics+audit diagnostic from zero
```

Componenta de **AUDIT v2.2** = clasificator XGBoost + **6 reguli** (F/recon/destruct/hijack/persist/anom),
servită pe AKS managed (imagine IMUABILĂ `@sha256`, replicas=2, hardenat), feed LIVE prin adapterul Log
Analytics (`30-adapter.yaml` → `/predict/raw`), metrici în Grafana (`audit_xgb_alerts_total{rule}`).
Reflectă EXACT fluxul real: cluster managed, audit→Log Analytics (NU fișier local), pipeline reproductibil.
Scenariul de prezentare: [`SCENARIU_PREZENTARE.md`](SCENARIU_PREZENTARE.md).

> Pe un cluster **managed** (AKS — ce se folosește în practică) audit-ul API-server-ului merge în **Log
> Analytics**, nu într-un fișier de pe nod. De-aceea calea reală e adapter LA→serviciu, NU streamer file-based.

---

## ⚠️ LEGACY — faza inițială de arhitectură (kind + model Transformer) — NU sistemul actual

> Tot ce urmează (`run_system.sh`, `run_demo.sh`, `run_demo_cluster.sh`, `run_demo_contrast.sh`,
> `demo_local.py`, serviciul `ids_service.py`, modelul `models/sequence_audit/` Transformer) provine din
> **faza inițială**, pe **kind**, ÎNAINTE de pivotul la cluster managed + hibridul XGBoost v2.2. **NU rula
> aceste demo-uri la apărare ca „IDS-ul meu"** — folosesc alt model (Transformer, contract `/predict` cu
> `{tokens,actor}`) și NU se aliniază cu dashboard-ul Grafana v2.2 (`audit_xgb_*`). Păstrate ca istoric.
> Componenta **FLOW** (rețea) de mai jos rămâne validă (separată de audit).

### [LEGACY] Sistem complet — ambele componente

```bash
./demo/run_system.sh    # LEGACY: audit = Transformer (nu v2.2)
```

Rulează ambele detectoare + smoke-test:
- **Componenta FLOW** (trafic de rețea / DDoS) — XGBoost + Autoencoder pe BCCC (validă, separată).
- **Componenta AUDIT** (abuz API K8s) — **Transformer (LEGACY, nu v2.2)**.
- **Validare**: `test_system.py`.

### Doar Componenta Flow (rețea)
```bash
python3 flow/demo_flow.py            # replay flow records BCCC (benign + DDoS)
```
Arată detecția hibridă cu defalcare `p_xgb · p_ae · score` (recall ~0.74 @ FPR 1%).
Artefactul de fuziune (calibratori Platt + prag) se regenerează cu `python3 flow/fit_fusion.py`.

### Smoke-test (validare ambele componente)
```bash
python3 test_system.py               # necesită serviciul Audit pe :8080
```

---

# Demo Componenta Audit (IDS runtime pentru Kubernetes)

Demo end-to-end **fără cluster**: reia evenimente de audit reale prin serviciul
IDS (FastAPI + model Transformer) și arată tot lanțul de detecție, exact ca în
producție, dar pe date deja capturate.

## Rulare (o singură comandă)

```bash
./demo/run_demo.sh                # complet (~75s, tot setul prin serviciu)
./demo/run_demo.sh --delay 0.2    # cu pauze între evenimente, pentru prezentare live
./demo/run_demo.sh --limit 1000   # rapid, pe un eșantion (~10s)
```

Launcher-ul pornește singur serviciul (dacă nu rulează) și apoi demo-ul.

## Demo LIVE pe cluster kind (varianta „wow")

Lanțul complet pe **infrastructură reală**: cluster Kubernetes → atacuri `kubectl`
reale → audit log → streamer → serviciu → **alerte live**.

```bash
./demo/run_demo_cluster.sh
```

Necesită Docker + kind + kubectl. Reutilizează clusterul `runtime-ids` dacă există
(altfel îl creează cu `cluster/setup_kind.sh`). Pornește streamer-ul care urmărește
audit log-ul în timp real, lansează 5 scenarii MITRE și afișează alertele detectate
de model (severitate + secvența de token-uri a atacului) + metricile streamer-ului.

Rezultat tipic: ~20+ alerte CRITICAL/HIGH pe traficul de atac, cu kill-chain-ul
vizibil (`list:secrets → create:serviceaccounts:token → create:clusterroles → …`).

Oprire cluster: `kind delete cluster --name runtime-ids`.

## Demo de CONTRAST — „nu sună din orice" (normal vs. atac)

Demonstrează că IDS-ul **tace pe trafic legitim** și reacționează **doar la atac**:

```bash
./demo/run_demo_contrast.sh
```

- **Faza A (trafic normal):** rulează `benign_workload.sh` — operații legitime,
  inclusiv acțiuni *admin* care seamănă cu atacuri (`get secrets`, `create token`,
  `create clusterrole`, `exec`). Rezultat tipic: **0–1 alerte** la zeci de evenimente.
- **Faza B (atac):** cele 5 scenarii MITRE → **~20–27 alerte**.

Contrastul (≈1 vs. ~25) dovedește că modelul învață **pattern-ul** atacului, nu
simpla prezență a unei acțiuni „sensibile" → FPR ~1%.

### Generare manuală de trafic normal

```bash
bash attacks/benign_workload.sh all 3   # deploy app + 3 runde (benign + admin)
bash attacks/benign_workload.sh round   # doar operații obișnuite
bash attacks/benign_workload.sh admin   # doar acțiuni admin legitime
```
Cu streamer-ul pornit, vei vedea că aproape toate produc verdict `benign` (fără alertă).

## Ce arată, pas cu pas

1. **Serviciul IDS** — model Transformer încărcat, endpoint `POST /predict`, metrici Prometheus la `/metrics`.
2. **Feed live** — traficul benign trece liniștit (p≈0), iar cele 6 scenarii MITRE declanșează alerte **CRITICAL** (p≈1.0).
3. **Rezultate agregate** (tot setul prin serviciul live): recall ≈ 0,98, precision ≈ 0,96, FPR ≈ 1%, plus recall per tip de atac.
4. **Corelare → incidente** (vederea analistului SOC): 3.330 alerte brute → 1 incident (`full_kill_chain`), 99,97% deduplicare, precision 1,0.

## Componente folosite

| Rol | Cale |
|---|---|
| Serviciu HTTP | `runtime_ids/service/ids_service.py` (FastAPI) |
| Model | `runtime_ids/models/sequence_audit/` (Transformer, F1 0,934) |
| Date | `runtime_ids/data/sequences.jsonl` (7.396 secvențe, 6 scenarii MITRE) |
| Corelator | `runtime_ids/correlator/` (pipeline pe 5 niveluri) |
| Demo | `runtime_ids/demo/demo_local.py` |

## Manual (pas cu pas, dacă vrei să arăți componentele separat)

```bash
# 1. pornește serviciul
cd runtime_ids/service
../../detection/bin/python3 -m uvicorn ids_service:app --port 8080

# 2. în alt terminal, rulează demo-ul
cd runtime_ids
../detection/bin/python3 demo/demo_local.py
```

## Oprire serviciu

```bash
pkill -f "uvicorn ids_service"
```
