# Scenariu de prezentare — Componenta Audit v2.2 (demo pe AKS managed)

Demo-ul reflectă **sistemul real**: un cluster **AKS managed**, audit→Log Analytics, IDS hibrid
**XGBoost + 6 reguli** servit digest-pinned, feed LIVE prin adapter, alerte în Grafana.
Orchestrator unic: `./demo/run_demo_aks.sh` (fazat).

> De ce NU kind: pe un cluster **managed** (ce se folosește în practică) control-plane-ul e gestionat
> de provider — audit log-ul API-server-ului NU e un fișier pe nod, ci merge în **Log Analytics**.
> Asta schimbă fundamental arhitectura de colectare (adapter LA, lag de ingestie de minute), de-aceea
> kind din faza inițială nu reprezintă realitatea.

---

## Pregătire (ÎNAINTE de apărare — fazele lente se fac din timp)

```bash
# o singură dată, din timp (au latență mare — NU le rula live):
./demo/run_demo_aks.sh --provision   # ~10 min: AKS+ACR+Log Analytics+audit diagnostic+SP
./demo/run_demo_aks.sh --deploy      # ~3-5 min: IDS v2.2 + Prometheus + Grafana + adapter LIVE
# verifică în avans că totul e sus:
./demo/run_demo_aks.sh --status
```
La apărare rulezi doar fazele **rapide și vizuale** (`--status`, `--train`, `--attack` + Grafana).

---

## Flux LIVE (~5-6 min)

### Pas 1 (20s) — context
> „Componenta de Audit detectează intruziuni din **log-ul de audit al API-server-ului Kubernetes**,
> pe un cluster **AKS managed**. E un sistem **hibrid**: un clasificator XGBoost + **6 reguli** de
> suport. Pe un cluster managed audit-ul merge în Log Analytics — un adapter îl citește în timp real
> și hrănește serviciul."

### Pas 2 (40s) — sistemul e LIVE și real
```bash
./demo/run_demo_aks.sh --status
```
Narează: „2 poduri, imagine **imuabilă pin-uită pe `@sha256`** (nu doar tag — imutabilitate reală),
hardenat (ne-root, readOnlyRootFS, NetworkPolicy). `healthz` arată versiunea **2.2-hybrid** și cele
**6 reguli** active: F / recon / destruct / hijack / persist / **anom**."

### Pas 3 (60s) — rezultatul ȘTIINȚIFIC (reproductibil, onest)
```bash
./demo/run_demo_aks.sh --train     # reproduce tabelul Wilson din ref_v2_all.csv (determinist)
```
Narează: „Reproduc rezultatul din CSV-ul versionat, **determinist** (`random_state=0`). Raportez
**Wilson 95% dublu**: **W(clasif)** = podeaua ML PURĂ, **W(FULL)** = podeaua sistemului hibrid.
Onest: ML-ul pur cade ~0% pe tacticile externe — acolo **regulile** prind. Asta validează empiric
**defense-in-depth**: ML+reguli > ML singur. Doar lateral și persistence trec pragul de 70% pe ambele."

### Pas 4 (90s) — ATAC LIVE → alertă în Grafana (end-to-end)
```bash
# terminal 1: urmărește adapterul
kubectl -n runtime-ids logs -l app=ids-audit-adapter -f
# terminal 2: lansează un atac real
./demo/run_demo_aks.sh --attack
# terminal 3 (deschis din timp): Grafana
./demo/run_demo_aks.sh --grafana    # http://localhost:3000 → panel audit_xgb_alerts_total{rule}
```
Narează: „Lansez un atac real `kubectl` — o **identitate kube-system fabricată** (graniță de
încredere). Adapterul îl citește din Log Analytics și face POST `/predict/raw`. Alerta apare cu
**`reasons`** — aici regula **`anom`** prinde SA-ul necunoscut. În Grafana vedeți spike-ul pe
`audit_xgb_alerts_total{rule="anom"}`."
> ONEST de spus: „alerta apare după **lag-ul de ingestie Log Analytics (~minute)** — e prețul unui
> cluster managed; pentru near-real-time s-ar folosi Event Hub."

### Pas 5 (40s) — onestitatea ca PUNCT FORTE
> „Sistemul își **cunoaște limitele**, măsurate adversarial pe 7 runde de audit: un **token-reuse pur**
> sau o identitate allowlistată **existentă** compromisă pot evada — regula `anom` prinde SA-uri
> *fabricate*, nu un controller existent furat (ar cere baseline comportamental, lucru viitor). Raportez
> aceste găuri explicit — un IDS care își știe podeaua reală e mai util operațional decât unul cu 100% suspect."

---

## Întrebări probabile + răspunsuri (v2.2, oneste)

| Întrebare | Răspuns |
|---|---|
| „Ce model rulează acum?" | XGBoost (30 trăsături) + 6 reguli de suport. `healthz` o confirmă live: `version: 2.2-hybrid`. |
| „De ce reguli, nu doar ML?" | Empiric: ML pur dă **0% pe tactici externe noi** (Wilson W(clasif)); regulile prind prin primitive/efecte. Defense-in-depth dovedit. |
| „Recreezi setul exact?" | Recreez **pipeline-ul** (determinist pe CSV); datele noi sunt *similare*, nu bit-cu-bit (telemetrie reală + timing). Documentat în DATASHEET (Gebru). |
| „De ce e lentă alerta?" | Lag de ingestie Log Analytics pe AKS managed (~minute) — onest, e o limită de infrastructură, nu de model. |
| „Ce NU prinde?" | Token-reuse pur fără efecte secundare; controller existent compromis (∈ known_allow); webhook persistence. Toate documentate (RAPORT §6). |
| „E reproductibil pe altă mașină?" | Pipeline + train da (CSV versionat). Provisioning-ul cere o subscripție Azure + `az login` (cluster managed real). |

---

## Oprire / curățenie
```bash
az aks stop -g intusion-detection-project -n intrusion-detection-aks   # oprește (păstrează tot)
# sau, pt infra creată de demo: az group delete -n rg-ids-demo --yes --no-wait
```
