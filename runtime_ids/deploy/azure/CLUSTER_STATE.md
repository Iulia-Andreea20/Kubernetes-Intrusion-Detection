# Stare cluster + runbook RESTORE (snapshot înainte de ștergere)

Snapshot al infrastructurii LIVE (2026-06-09) ca să poți **șterge resursele** (cost) și **recrea identic** apoi.
Tot ce e nevoie e versionat în git (manifeste, cod, model, dataset) + imaginile pe Docker Hub (persistă peste ștergere).

---

## 1. STAREA LIVE capturată (ce se șterge)

**Azure** (subscripție „Azure for Students" `31bb85a2-bdc2-420b-841e-13ab01c07038`):
| Resursă | Valoare |
|---|---|
| Resource group | `intusion-detection-project` |
| AKS | `intrusion-detection-aks` — k8s **1.34**, **2× Standard_DS2_v2**, `northeurope` |
| Log Analytics | `law-ids-aks` — customerId (CID) **`39628155-ae16-4624-90d3-41d58489f713`** |
| Diagnostic setting | `ids-audit`: `kube-audit` + `kube-audit-admin` → workspace (CRITIC: fără el nu curge audit) |
| Role assignment | identitate **kubelet** `481aa69d-…` → **„Log Analytics Reader"** pe workspace (auth adapter, managed identity) |

**Kubernetes** (namespace `runtime-ids`) — imagini (Docker Hub, persistă peste ștergere):
| Deployment | Imagine |
|---|---|
| `ids-audit-xgb` (v2.4) | `andreeagrigore/runtime-ids-audit:2.4@sha256:7ed969a203dfeb50fdda16b7f96a9475e13fe5e1e013e8ca6d53dd55124c824a` |
| `ids-audit-adapter` | `andreeagrigore/ids-audit-adapter:2.3` |
| `ids-flow` / `falco-exporter` | `andreeagrigore/runtime-ids:1.1` |
| obs | `prom/prometheus:v2.54.1`, `grafana/grafana:11.1.0`, `prom/alertmanager:v0.27.0`, `mailhog/mailhog:v1.0.1` |

**Versionat în git** (NU se pierde): toate manifestele (`k8s/`), codul (serviciu+adapter+pipeline), modelul
(`models/audit_hybrid_v2/`), config (`pipeline_config.json` cu allowlist+known_allow), datasetul (`ref_v2_all.csv`, 50 513 ferestre).

---

## 2. ȘTERGERE (oprește costul)

```bash
# Varianta A — PĂSTREAZĂ infra, oprește doar compute (cost redus, restore instant):
az aks stop -g intusion-detection-project -n intrusion-detection-aks

# Varianta B — ȘTERGE TOT (cost zero; recrearea cere ~15 min — vezi §3):
az group delete -n intusion-detection-project --yes --no-wait
```

---

## 3. RECREARE „from zero" (verifică reproductibilitatea)

```bash
# 0. login
az login

# 1. provisioning (AKS + LA + diagnostic kube-audit + rol kubelet→LA Reader). ~10 min.
#    Default-urile reproduc EXACT config-ul de mai sus. Scrie env.generated cu noul LA_WORKSPACE_ID.
bash runtime_ids/deploy/azure/setup_aks.sh

# 2. deploy IDS v2.x + observability + adapter LIVE (pull imagini din Docker Hub). ~3-5 min.
bash runtime_ids/deploy/azure/deploy_obs_aks.sh

# 3. verifică (healthz 2.x-hybrid, 6 reguli, 2 poduri pe noduri diferite):
./runtime_ids/demo/run_demo_aks.sh --status

# 4. (opțional) RECREEAZĂ setul de date: actori + atacuri + export (folosește noul CID din env.generated):
bash runtime_ids/deploy/azure/collect/setup_actors.sh
bash runtime_ids/deploy/azure/collect/attack_wilson_push.sh         # + alte attack_*.sh
source runtime_ids/deploy/azure/env.generated                       # exportă LA_WORKSPACE_ID
(cd runtime_ids/deploy/azure/collect && LA_WORKSPACE_ID=$LA_WORKSPACE_ID python export_v2.py)   # → ref_v2_all.csv NOU

# 5. reproduce tabelul Wilson (determinist, din CSV — merge ȘI fără cluster):
./runtime_ids/demo/run_demo_aks.sh --train

# 6. atac live → adapter → Grafana:
./runtime_ids/demo/run_demo_aks.sh --attack
./runtime_ids/demo/run_demo_aks.sh --grafana
```

---

## 4. CE e IDENTIC la recreare vs CE diferă (onest)

**IDENTIC (bit-cu-bit / garantat):**
- Arhitectura, manifestele hardenate, imaginile (digest `@sha256` — exact aceiași biți din Docker Hub).
- Modelul + config (versionate) → comportament de detecție identic.
- Tabelul Wilson (`train_v2.py`, `random_state=0`) reprodus **bit-cu-bit** din `ref_v2_all.csv` versionat.

**DIFERĂ (intrinsec, cluster managed nou):**
- **CID-ul Log Analytics** (workspace nou → GUID nou) → de-aceea `export_v2.py` îl ia din `LA_WORKSPACE_ID`
  (env.generated), nu hardcodat. La fel, identitatea kubelet are alt objectId (rolul se re-asignează automat în setup_aks).
- **Datele de audit re-colectate** sunt NOI (telemetrie reală + timing) — *similare*, nu aceleași 50 513 ferestre.
  De-aceea CSV-ul e versionat ca **referință** (pipeline reproductibil ≠ date bit-identice — vezi DATASHEET §6-7).

> Concluzie: recrearea e **funcțional identică** (aceeași arhitectură, model, pipeline, detecție), nu bit-identică pe
> GUID-urile generate de Azure și pe telemetria live — exact ce se așteaptă de la un cluster managed reprovizionat.

---

## 5. Prerechizite recreare
- `az login` cu rol pe subscripție care permite role assignment (Owner/User Access Admin pe RG — îl ai pe RG-ul tău).
- `kubectl`. Imaginile `andreeagrigore/*` pe Docker Hub trebuie să fie pullabile (publice) — sunt deja pushate.
- NU necesită: SP (managed identity), ACR (Docker Hub), rebuild (doar dacă schimbi codul).
