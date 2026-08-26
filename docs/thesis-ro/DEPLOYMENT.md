# Documentație de Deployment și Utilizare — Sistem IDS multi-componentă pentru Kubernetes

> **Surse:** toate căile, comenzile, porturile, resursele și valorile de configurare din acest document sunt
> extrase direct din manifestele, Dockerfile-urile și codul din depozit (`runtime_ids/`, `k8s/`, `cluster/`).
> Elementele neimplementate sunt marcate explicit ca **future work**. Verificat la 2026-06-04.

---

## 1. Scop și moduri de utilizare

Sistemul este un IDS *defense-in-depth* pentru Kubernetes, definit pe trei surse de detecție independente —
**2 funcționale** (Audit + Flow) **+ 1 evaluată, neaplicabilă pe kernelul AKS `5.15-azure`** (Falco) — care alimentează
un corelator și o stivă de observabilitate. Cele trei planuri de date distincte:

- **Audit (plan de control)** — serviciu FastAPI care, în deployment-ul curent, rulează un model **Transformer pe
  secvențe** de evenimente kube-audit (`runtime_ids/service/ids_service.py`, model `runtime_ids/models/sequence_audit/`;
  pe AKS `sequence_audit_cloud_max/` prin `RUNTIME_IDS_MODEL_DIR`).
  *Notă:* modelul **XGBoost** pe trăsături comportamentale (`runtime_ids/models/audit_api_xgb/`, antrenat pe setul de
  date personalizat din `reference_dataset/`) este modelul de **referință al dataset-ului**; poate înlocui Transformer-ul,
  dar serviciul live folosește implicit varianta secvențială.
- **Flow (rețea)** — detector hibrid XGBoost + Autoencoder pe trăsături de flux, antrenat pe BCCC-cPacket-Cloud-DDoS-2024
  (`runtime_ids/flow/{flow_detector,flow_exporter}.py`; modele în `retraining_bccc/models/`, `autoencoder_bccc/`).
- **Falco (runtime/container)** — senzor eBPF bazat pe reguli/semnături. **Deployat, funcțional și acum IaC reproductibil**
  (Falco 0.44.x, modern eBPF pe kernel AKS 5.15). Instalat versionat prin `deploy/azure/setup_falco.sh` cu values
  committed (`deploy/azure/k8s/falco-values.yaml`: `driver.kind=modern_ebpf` + `http_output` către exporter), integrat ca
  pas `[7/8]` în `deploy_aks.sh`. **Verificat end-to-end:** un `cat /etc/shadow` într-un pod a declanșat regula *„Read
  sensitive file untrusted"* (tag MITRE T1555), propagată prin `http_output` la `falco-exporter` →
  `falco_alerts_total{rule=...,pod=...}` (Prometheus). Integrat în corelator (`correlator/falco_source.py`, mapare
  pod→user) și evaluat TP/FP (`falco_eval.py`); dashboard `falco_container.json` auto-provisionat. Detalii: `FALCO_RUNTIME.md`.
  **Ce rămâne (onest):** corelarea live a celor 3 surse e demonstrată scriptat/offline (`demo_falco_correlate.py`), nu
  cablată ca pod. Prin natură, Falco e bazat pe semnături (fără model ML / dataset propriu — intenționat).

### 1.1 Monitorizare continuă in-cluster (online)
Audit și Flow rulează ca pod-uri permanente, expun metrici Prometheus, iar alertele sunt evaluate de Prometheus și
rutate prin Alertmanager către email.
- **Audit:** streamer-ul (self-managed) sau adapter-ul (AKS) citește continuu evenimentele kube-audit, le tokenizează
  în ferestre de lungime 20 (`RUNTIME_IDS_SEQ_LEN=20`) și le trimite prin `POST /predict` la `ids-service:8080`
  (`audit_streamer.py:180`, `ids_service.py:268`). Serviciul expune și `POST /predict/raw` (tokenizare server-side).
- **Flow:** la pornire, `flow_exporter.py` scorează în loturi un eșantion BCCC copt în imagine
  (`--limit 6000 --batch 120 --delay 0.5`) și expune contoare pe portul 9092. **Limitare:** nu există captură de trafic
  live — sursa Flow este offline (eșantion static).

### 1.2 Analiză offline / batch
Corelatorul rulează ca instrument **offline**, nu ca serviciu in-cluster.
- `runtime_ids/correlator/run_correlator.py` citește predicții din `models/{xgboost_audit,lightgbm_audit,sequence_audit}/`
  (intrări **hardcodate**), aplică pipeline-ul în 5 niveluri și scrie `correlator_metrics.json` + `incidents.json` în
  `models/correlator/`.
- **Limitare importantă:** corelatorul **nu** este un pod și **nu** primește alerte live. Mai mult, intrările sale
  implicite sunt **variante de model de audit** (xgboost/lightgbm/sequence) — componenta **Flow NU este** printre ele.
  Așadar „corelarea integrată a 3 surse" descrie arhitectura-țintă, nu pipeline-ul cablat azi.

### 1.3 Per-componentă vs. integrat
- **Per-componentă:** fiecare detector poate rula independent (doar Audit + streamer, sau doar Flow). Imaginea unică
  rulează oricare rol prin suprascrierea câmpului `command` în manifest.
- **Integrat:** Audit + Flow **funcționale** + (Falco — **evaluat, neaplicabil pe kernelul AKS `5.15-azure`**) + observabilitate, cu corelatorul aplicat offline peste predicții.

---

## 2. Arhitectură de deployment

Toate componentele rulează în namespace-ul **`runtime-ids`** (`runtime_ids/deploy/k8s/00-namespace.yaml`).

### 2.1 Componente și tip de workload

| Componentă | Workload | Manifest | Port | Comandă |
|---|---|---|---|---|
| Audit | Deployment (1 replică) | `deploy/k8s/10-audit.yaml` | 8080 | `uvicorn ids_service:app` (implicit din imagine) |
| Flow | Deployment (1 replică) | `deploy/k8s/20-flow.yaml` | 9092 | `flow_exporter.py --port 9092 --limit 6000 --batch 120 --delay 0.5` |
| Streamer | **DaemonSet** (control-plane) | `deploy/k8s/30-streamer.yaml` | 9100 | `audit_streamer.py` |
| Prometheus | Deployment (1) | `deploy/k8s/40-prometheus.yaml` | 9090 | scrape 5s |
| Alertmanager | Deployment (1) | `deploy/k8s/50-alertmanager.yaml` | 9093 | SMTP → MailHog |
| MailHog | Deployment (1) | `deploy/k8s/60-mailhog.yaml` | 1025/8025 | SMTP de test |
| Grafana | Deployment (1) | `deploy/k8s/70-grafana.yaml` | 3000 | admin/admin, 2 dashboards |

Servicii ClusterIP: `ids-service:8080` (selectează `app: ids-audit`) și `ids-flow:9092`.

### 2.2 De ce este streamer-ul un DaemonSet pe control-plane
Streamer-ul citește fișierul real de audit prin `hostPath` read-only `/var/log/kubernetes/audit`
(`30-streamer.yaml`). Fișierul există doar pe nodul control-plane, deci DaemonSet-ul tolerează taint-ul
`node-role.kubernetes.io/control-plane:NoSchedule`. Env: `RUNTIME_IDS_AUDIT_LOG=/var/log/kubernetes/audit/audit.log`,
`RUNTIME_IDS_SERVICE_URL=http://ids-service:8080`, `RUNTIME_IDS_STREAMER_METRICS_PORT=9100`.
(Default-ul din cod este `http://ids-service.runtime-ids.svc:80`, suprascris în manifest la portul 8080.)

### 2.3 Fluxul de date

```
[kube-audit] --(fișier pe self-managed / Log Analytics pe AKS)--> Streamer/Adapter
     --(POST /predict, ferestre de 20 tokeni verb:resource:subresource)--> ids-service:8080 (Transformer)
     --> metrici runtime_ids_alerts_total{severity} / runtime_ids_predictions_total{verdict}

[eșantion BCCC copt în imagine] --> ids-flow:9092 (XGBoost+Autoencoder, fuziune Platt)
     --> metrici runtime_ids_flow_alerts_total / runtime_ids_flow_predictions_total

Prometheus (scrape 5s: ids-service:8080, ids-flow:9092, falco-exporter:9093)
     --> reguli de alertă --> Alertmanager (group_wait 5s, repeat 30m)
     --> SMTP MailHog:1025 --> email soc@k8s-ids.local
Grafana <--PromQL-- Prometheus:9090 (dashboards ids_soc, ids_mlops)
```

- **Fuziune Flow** (`flow/fusion.json`): scor = 0,7·XGBoost_Platt + 0,3·Autoencoder_Platt, prag **0,7339936698382703**
  (fixat la FPR = 1%), `input_dim = 317`.
- **Pipeline corelator** (`correlator/pipeline.py`): L1 threshold/componentă → L2 calibrare Platt → L3 corelare pe actor
  + fereastră de timp (implicit **60 s**) → L4 lanțuri MITRE ATT&CK (`chains.py`, boost ×3,0 pt `full_kill_chain`) →
  L5 severitate (`CRITICAL≥0,95`, `HIGH≥0,85`, `MEDIUM≥0,70`, `LOW≥0,50`).

### 2.4 Diferențe pe AKS (managed)
- Streamer-ul file-based este **înlocuit** (nu relocat) de `ids-audit-adapter` (`deploy/azure/k8s/30-adapter.yaml`),
  un Deployment care interoghează kube-audit din Log Analytics prin KQL (`POLL_INTERVAL=15`, `LOOKBACK_MIN=10`) și
  hrănește același `ids-service:8080`. **Motivul** este arhitectural: pe AKS nodul de control-plane **nu este vizibil/
  programabil**, deci topologia DaemonSet-hostPath e *imposibilă*, nu doar nerecomandată (vezi §6.1).
- Imagini din Docker Hub: `andreeagrigore/runtime-ids:1.1`, `andreeagrigore/ids-audit-adapter:1.0`.
- `imagePullPolicy: Always` pentru audit și adapter; **excepție**: `80-falco-exporter.yaml` folosește `IfNotPresent`.

---

## 3. Cerințe de infrastructură + justificare tehnică

### 3.1 Cluster Kubernetes (kind pentru dev / AKS pentru managed)
**De ce:** orchestrează pod-urile, oferă networking + DNS intern (rezoluția `ids-service`, `ids-flow`, `prometheus`…),
programare DaemonSet pe control-plane și probe readiness/liveness. Dev: `cluster/setup_kind.sh` + `cluster/kind-config.yaml`.
Managed: `deploy/azure/deploy_aks.sh`.

### 3.2 Acces la kube-audit (și de ce diferă pe managed)
**De ce:** componenta Audit nu are date fără jurnalul de audit al API server-ului.
- **Self-managed (kind):** politica `cluster/audit-policy.yaml` jurnalizează la nivel `RequestResponse` pe suprafețele
  de risc (`pods/exec`, `pods/attach`, `pods/portforward`, obiecte RBAC, `serviceaccounts/token`, `pods`, workload-uri
  `apps`), `Request` pe secrets/configmaps, restul `Metadata`, cu zgomotul (`/healthz*`, `/metrics`) la `None`.
  Cablare reală în `cluster/kind-config.yaml`: flag-uri apiserver `audit-log-path=/var/log/kubernetes/audit/audit.log`
  + `audit-policy-file`, `extraVolumes` (apiserver→nod) și `extraMounts` (nod→host `./audit-logs`), cu **rotație**
  (`audit-log-maxage=7`, `maxbackup=3`, `maxsize=100`MB). *Operațional:* streamer-ul urmărește un fișier care se rotește.
- **AKS managed:** control-plane-ul e gestionat de Azure și **nu** expune `/var/log/kubernetes/audit`. De aceea jurnalele
  merg în Log Analytics, iar adapter-ul le citește prin KQL. `deploy_aks.sh` (1) descoperă workspace-ul Log Analytics din
  addon-ul **Container Insights/omsagent** (`addonProfiles.omsagent.config.logAnalyticsWorkspaceResourceID`) și rulează
  `az aks enable-addons -a monitoring` dacă lipsește; (2) creează **o singură diagnostic setting `ids-audit`** cu **două**
  categorii de loguri (`kube-audit`, `kube-audit-admin`); (3) creează un service principal cu rol Azure **Log Analytics
  Reader** pe workspace. → Container Insights activat este o **prerechizită reală**.
- **Limitare:** lag de ingestie de câteva minute în Log Analytics (`audit_loganalytics_adapter.py`).

### 3.3 Captarea fluxurilor de rețea
**De ce:** componenta Flow necesită trăsături de flux (317 features, `fusion.json`).
- **Implementat:** scorare offline pe un eșantion BCCC copt în imagine (`deploy/test_holdout_sample.csv` → copiat la
  `retraining_bccc/data/holdout_split/test_holdout.csv` în Dockerfile).
- **Future work:** captura de trafic live (Cilium Hubble / Calico flow logs / eBPF) nu este integrată.

### 3.4 Acces la nivel de nod / eBPF pentru Falco
**De ce:** Falco necesită kernel Linux cu eBPF pentru trasarea syscall-urilor — un **DaemonSet privilegiat** cu acces la
kernelul gazdă (`CAP_SYS_ADMIN`/`CAP_BPF` sau `privileged: true`). Chart-ul Helm Falco creează exact acest DaemonSet
privilegiat (driver `modern_ebpf`); pe AKS (kernel 5.15) a funcționat fără cost Azure suplimentar.
- **Realizat și reproductibil (IaC):** instalarea e versionată în `deploy/azure/setup_falco.sh` + `falco-values.yaml`
  (repo Helm → ConfigMap exporter → `helm upgrade --install` cu `modern_ebpf` + `http_output`), apelată din `deploy_aks.sh`
  pas `[7/8]`. Falco capturează acțiuni de runtime în container (shell, citire `/etc/shadow` și a token-ului de SA) — exact
  golul pe care planul de audit API NU îl vede (după `exec`, interiorul containerului e invizibil audit-ului).
- **Pipeline-ul observabilității, reparat și verificat:** Falco `http_output` → `falco-exporter` (`POST /falco`) →
  `falco_alerts_total` → scrape Prometheus → regula `FalcoRuntimeDetected`. `setup_falco.sh` **creează ConfigMap-ul
  `falco-exporter-code`** (din `falco_exporter.py`) pe care manifestul `80-falco-exporter.yaml` îl montează — deci
  placeholder-ul anterior rupt (ConfigMap lipsă) este acum funcțional. Verificat: `cat /etc/shadow` într-un pod →
  `falco_alerts_total{rule="Read sensitive file untrusted",pod="pwn"} 1` în exporter.
- **De reținut:** privilegiile (DaemonSet privilegiat, eBPF) provin din chart-ul Falco, nu dintr-un YAML propriu — fixate
  prin versiunea chart-ului în `setup_falco.sh`.

### 3.5 Resurse compute / memorie (din manifeste)

| Componentă | requests | limits |
|---|---|---|
| Audit (`10-audit.yaml`) | 100m / 256Mi | 1 / 1Gi |
| Flow (`20-flow.yaml`) | 200m / 512Mi | 2 / 2Gi |
| Streamer (`30-streamer.yaml`) | 50m / 128Mi | 500m / 512Mi |
| Adapter AKS (`30-adapter.yaml`) | 50m / 128Mi | 500m / 512Mi |
| Prometheus | 100m / 256Mi | 1 / 1Gi |
| Alertmanager | 50m / 64Mi | 300m / 256Mi |
| MailHog | 20m / 32Mi | 200m / 128Mi |
| Grafana | 100m / 128Mi | 1 / 512Mi |

**De ce:** inferența Transformer (CPU) și scorarea XGBoost+Autoencoder sunt CPU-bound; Flow procesează DataFrame-uri mari
în memorie. **Nu** este necesar GPU (torch CPU `2.2.2`). Conflictul OpenMP/PyTorch e mitigat prin `KMP_DUPLICATE_LIB_OK=TRUE`
și `OMP_NUM_THREADS=2` (Dockerfile + `20-flow.yaml`).

### 3.6 Stocare / PVC
**De ce:** modelele trebuie disponibile în filesystem-ul pod-ului.
- **Implementat:** modelele sunt **coapte în imagine** (Dockerfile copiază `sequence_audit/`, `sequence_audit_cloud_max/`,
  `vocab.json`, `xgboost_bccc/model.json`, `autoencoder_bccc/`, eșantionul BCCC). Prometheus folosește
  `--storage.tsdb.path=/prometheus` **fără PVC**.
- **Limitare:** TSDB Prometheus e **efemer** (se pierde la restart). Producție → PVC dedicat (neconfigurat).

### 3.7 Stiva de observabilitate
**De ce:** detecțiile devin acționabile doar prin metrici → reguli → alerte → email/dashboard.
- **Prometheus** `v2.54.1` (scrape 5s la `ids-service:8080`, `ids-flow:9092`, `falco-exporter:9093`); reguli
  `IDSAttackDetected` (`increase(runtime_ids_alerts_total{severity=~"CRITICAL|HIGH"}[1m]) > 0`) și `FlowAttackDetected`.
- **Alertmanager** `v0.27.0` → receiver `email-soc` prin SMTP `mailhog:1025` (`group_wait 5s`, `repeat_interval 30m`,
  `smtp_require_tls: false`); expeditor `ids-alert@k8s-ids.local`, destinatar `soc@k8s-ids.local`.
- **MailHog** `v1.0.1` (SMTP de test). Producție → `smtp_smarthost` corporativ (neimplementat scriptat).
- **Grafana** `11.1.0` cu datasource + **exact 2 dashboards** provisionate (`ids_soc`, `ids_mlops`). Fișierul
  `falco_container.json` există în repo dar **NU** este provisionat → **nu** există dashboard Falco live.

---

## 4. Prerechizite și pași de deployment

### 4.1 Prerechizite
- **Dev:** Docker, `kubectl`, `kind` (verificate de `cluster/setup_kind.sh`).
- **AKS:** `az` CLI; cluster AKS existent; drept de a crea service principal și diagnostic settings;
  **addon Container Insights/monitoring activabil** (adapter-ul depinde de el).
- Imaginea se construiește din **rădăcina** repo-ului (contextul trebuie să cuprindă `retraining_bccc/`).

### 4.2 Construirea imaginii (`runtime_ids/deploy/Dockerfile`)
```
docker build -f runtime_ids/deploy/Dockerfile -t runtime-ids:1.0 .
```
`python:3.11-slim`, `torch==2.2.2` (CPU) + `requirements-cluster.txt`, copiază codul + modelele + eșantionul BCCC.
`CMD` implicit = Audit (`uvicorn ids_service:app --port 8080`); Flow și streamer suprascriu `command`.

### 4.3 Deployment local (kind) — `runtime_ids/deploy/deploy.sh`
1. `kind load docker-image runtime-ids:1.0`. 2. `kind load` imaginile de observabilitate. 3. Aplică `00-namespace.yaml`.
4. ConfigMaps Grafana din `observability/grafana/` (doar `ids_soc.json` + `ids_mlops.json`). 5. `kubectl apply -f k8s/`
+ `rollout status deploy/ids-audit`. Acces UI: Grafana `:3000` (admin/admin), MailHog `:8025` prin `port-forward`.
Prealabil, clusterul cu audit logging: `cluster/setup_kind.sh`.

### 4.4 Deployment pe AKS — `runtime_ids/deploy/azure/deploy_aks.sh`
Credențiale `kubectl` → descoperă/activează workspace Log Analytics (Container Insights) → **o** diagnostic setting
`ids-audit` (2 categorii) → service principal *Log Analytics Reader* → namespace + ConfigMap `ids-azure-config` + Secret
`ids-azure-sp` → ConfigMaps Grafana → `kubectl apply -f azure/k8s/` (audit + flow + adapter + falco-exporter) +
reutilizează observabilitatea din `deploy/k8s/`. Scriptul reamintește teardown-ul (`az group delete`, `az ad sp delete`)
pentru control de cost.

### 4.5 Analiză offline cu corelatorul
```
python runtime_ids/correlator/run_correlator.py
```
Citește `models/{xgboost_audit,lightgbm_audit,sequence_audit}/predictions.csv`; scrie `models/correlator/incidents.json`
+ `correlator_metrics.json`.

---

## 5. Topologii de deployment recomandate

### 5.1 Minimal — doar Audit (control-plane)
`ids-audit` (Deployment) + `ids-streamer` (DaemonSet) + Prometheus + Alertmanager + MailHog. Cea mai ieftină;
necesită audit logging activat. Utilă pentru detecția abuzului de API (exec, RBAC, furt de token).

### 5.2 Complet — surse multiple + corelator + observabilitate
Audit + Flow + (Falco **evaluat, neaplicabil pe kernelul AKS `5.15-azure`**) + observabilitate completă. Corelatorul rulează **offline** (nu e pod), iar azi
corelează **variante de model de audit**, nu trio-ul live Audit+Flow+Falco. Recomandat pentru demonstrația academică.

### 5.3 Managed AKS vs. self-managed
- **Self-managed / kind:** streamer file-based (`hostPath`), imagini locale (`IfNotPresent`), audit-policy aplicată manual.
- **Managed AKS:** `ids-audit-adapter` (Log Analytics + KQL) în loc de streamer, imagini Docker Hub (`Always`), service
  principal + diagnostic settings + Container Insights. Atenție la cost (vezi §6.3).

---

## 6. Considerații operaționale

### 6.1 Scalare / HA
- Toate componentele core au **`replicas: 1`**; streamer = DaemonSet pe control-plane (nod unic).
- **Constrângere de topologie:** pe self-managed cu un singur control-plane există un singur `audit.log`; HA multi-control-plane
  ar dispersa fișierele de audit (netestat). Pe **AKS** topologia streamer-hostPath e **imposibilă** (control-plane invizibil)
  → de aceea se folosește adapter-ul Log Analytics.
- **Limitare:** fără HPA / PodDisruptionBudget / multi-zonă în stiva `runtime-ids` (HPA există doar într-un deployment
  legacy `llm-ids-inference`, separat).

### 6.2 Securitate / RBAC / NetworkPolicy
- **RBAC:** nu există manifeste RBAC dedicate pentru pod-urile `runtime-ids` (service account implicit). Accesul la audit
  **nu** folosește RBAC K8s: pe self-managed e la nivel de **filesystem** (`hostPath` read-only); pe AKS e **Azure RBAC**
  (rolul *Log Analytics Reader* al service principal-ului) — o cerință de autorizare pe partea Azure, nu K8s.
- **Securitate pod:** `deploy/k8s/` nu setează `securityContext` (variante mai stricte cu `runAsNonRoot`/
  `readOnlyRootFilesystem` apar în `service/k8s/` și `streamer/k8s/`).
- **NetworkPolicy:** absentă în stiva aplicată de `deploy.sh` (politici există doar în `k8s/networkpolicy.yaml`,
  `service/k8s/networkpolicy.yaml`).
- **Secrete:** credențialele Azure (`ids-azure-sp`) sunt Secrets K8s simple, fără rotație/manager extern.
- **TLS:** toate serviciile sunt HTTP simplu; SMTP fără TLS. **Limitare** pentru producție.

### 6.3 Cost
- **Compute AKS:** Flow poate consuma până la 2 CPU; fără Spot/quotas/autoscaling. Teardown documentat în `deploy_aks.sh`.
- **Log Analytics (recurent, separat de compute):** `kube-audit` + `kube-audit-admin` sunt categorii cu volum mare,
  **facturate pe GB ingerați**; plus addon-ul Container Insights forțat-activat. De monitorizat cota gratuită (~5GB).

### 6.4 Fals-pozitive, prag și histerezis
- **Prag Flow:** FPR = 1% → `0,7339936698382703`; fuziune ponderată 0,7/0,3 calibrată Platt.
- **Praguri corelator:** la FPR-țintă 1%/componentă (`threshold_at_fpr`); severitate pe 4 niveluri; boost de lanț plafonat.
- **Reguli de alertă:** `increase(...[1m]) > 0`, `for: 0s` — orice alertă declanșează imediat; deduplicare Alertmanager
  doar pe `alertname`. Corelarea cross-componentă reală se face **doar offline**. Risc de email-uri repetate (mitigat parțial
  de `repeat_interval: 30m`). **Nu** există histerezis live in-cluster.
- **Histerezis la nivel de model (audit):** în evaluarea offline a modelului XGBoost de audit, agregarea pe episod cu
  **K ≥ 2 ferestre** reduce FPR-ul operațional (vezi `reference_dataset/DATASHEET.md`); nu este încă portat în pipeline-ul live.

### 6.5 Limitări și future work (sintetic)
- **Falco/eBPF runtime:** **deployat, funcțional, IaC reproductibil și verificat** (`setup_falco.sh` + `falco-values.yaml`,
  integrat în `deploy_aks.sh`; exporter reparat + dashboard auto-provisionat). **Rămâne doar:** corelarea live in-cluster a
  celor 3 surse (azi scriptată/offline prin `demo_falco_correlate.py`).
- **Captură flux de rețea live:** neimplementată (Flow scorează doar eșantion static BCCC).
- **Corelator in-cluster live:** neimplementat; offline, pe variante de model de audit (Flow neinclus implicit).
- **Persistență Prometheus:** TSDB efemer (fără PVC).
- **HA/scalare:** 1 replică/componentă, fără HPA/PDB/multi-zonă.
- **RBAC dedicat, NetworkPolicy în stiva principală, TLS/mTLS:** neconfigurate în `deploy/k8s/`.
- **SMTP de producție:** neimplementat scriptat (MailHog doar test).

---

## Anexă — fișiere-cheie (verificate în depozit)
- **Manifeste kind:** `runtime_ids/deploy/k8s/{00-namespace,10-audit,20-flow,30-streamer,40-prometheus,50-alertmanager,60-mailhog,70-grafana}.yaml`
- **Manifeste AKS:** `runtime_ids/deploy/azure/k8s/{10-audit,20-flow,30-adapter,80-falco-exporter}.yaml`, `audit_loganalytics_adapter.py`, `deploy_aks.sh`
- **Imagine / deploy:** `runtime_ids/deploy/{Dockerfile,deploy.sh}`, `requirements-cluster.txt`
- **Audit/cluster:** `runtime_ids/cluster/{audit-policy.yaml,setup_kind.sh,kind-config.yaml}`
- **Cod:** `runtime_ids/service/ids_service.py`, `runtime_ids/flow/{flow_detector,flow_exporter}.py` + `fusion.json`, `runtime_ids/streamer/audit_streamer.py`, `runtime_ids/correlator/{pipeline,chains,run_correlator}.py`
- **Model de referință al dataset-ului:** `runtime_ids/models/audit_api_xgb/`, `runtime_ids/deploy/azure/collect/reference_dataset/DATASHEET.md`
