# HANDOFF / REFERINȚĂ — IDS Kubernetes (pentru chat-urile următoare cu Claude)

> Document de referință cu starea sistemului + tot ce s-a făcut în sesiunea de evaluare externă (iunie 2026).
> Citește-l la începutul unui chat nou ca să ai contextul. Cifrele sunt din rulări reale; N mic ⇒ ilustrativ, nu statistic.

## 0. Pe scurt (TL;DR)
- IDS K8s pe 3 componente: **Flow** (rețea/DDoS), **Audit** (plan de control, model de referință **XGBoost** pe 15 trăsături), **Falco** (runtime). Corelator + observabilitate (Prometheus/Grafana/Alertmanager/MailHog).
- Sesiunea asta = **validare anti-circularitate** a modelului de Audit, cu **unelte de atac terțe**. Concluzia majoră: **cifrele sintetice mari erau optimiste/artefactuale**, iar reconul-`can-i` e **fundamental ambiguu** cu automatizarea benignă.

## 1. Constrângeri permanente (RESPECTĂ-LE)
- Subscripție: **„Azure for Students"** (`31bb85a2-bdc2-420b-841e-13ab01c07038`).
- `az monitor log-analytics query` e rupt local → folosește **`az rest`** la `api.loganalytics.io` (vezi `export_scale.py`).
- NU atinge modelul de **Flow/rețea** (`retraining_bccc/models/xgboost_bccc/`).
- Mediu Intel Mac: env `./detection` (Python 3.11), torch 2.2.2, numpy<2. Lockfile: `requirements-detection-lock.txt`.

## 2. Cluster Azure (AKS)
- RG **`intusion-detection-project`** (typo intenționat în nume), AKS **`intrusion-detection-aks`** (northeurope, 2× Standard_DS2_v2, Azure CNI, k8s 1.34.7), workspace LA **`law-ids-aks`** (customerId `39628155-ae16-4624-90d3-41d58489f713`).
- A fost **șters și reconstruit** în sesiune → runbook complet: **`runtime_ids/deploy/azure/RESTORE_AZURE.md`** + backup live în `_cluster_backup/`.
- Diagnostic settings: `kube-audit` + `kube-audit-admin` → LA. Audit-ul curge abundent (~2M+ evenimente).
- **Oprire cost fără a pierde nimic:** `az aks stop -g intusion-detection-project -n intrusion-detection-aks` (și `az aks start` la revenire). NU șterge (rebuild costisitor).
- Componente live în `runtime-ids`: ids-audit-xgb, ids-flow, falco(+exporter), prometheus, alertmanager, mailhog, grafana. Acces: `kubectl -n runtime-ids port-forward svc/grafana 3000:3000` (admin/admin).

## 3. Setul de date de referință (Audit) + documentație
- Locație: `runtime_ids/deploy/azure/collect/reference_dataset/` (CSV-uri v1.1 = artefactul ML; JSONL/events_rich = snapshot v1.0).
- v1.1: **35 951 ferestre** (train 25 042 / test 10 909), atac 3 048 / benign 32 903, **24 sesiuni** (1-16 train, 17-24 test, sesiune-disjunct), **52 episoade**, **15 trăsături**.
- O „intrare" = **fereastră glisantă de 20 evenimente/actor** → 15 trăsături comportamentale. Identitatea EXCLUSĂ din model (anti-leakage).
- Compoziție benign: ~72% trafic sistem/infra (aksService etc.), 12% controllere native, 4% operatoare (cert-manager/ArgoCD/Prometheus), ~8% actori umani, scanner conformitate 3.5%.
- 4 profiluri atac: stolen-token (victim-sa), valid-abuse (adversary-external), low-and-slow (adversary-insider), recon (recon-sa).
- **Roster curățat**: 6 actori benigni *activi* (sre-oncall, devops-pipeline, platform-engineer, security-auditor, ci-deployer, platform-admin) + 2 atacatori cert + 2 SA. (Ceilalți 6 din roster făceau 0 ferestre → eliminați din `setup_actors.sh`.)
- **Documente cheie (toate aliniate cu CSV-urile):**
  - `runtime_ids/docs/SET_DATE_SI_MODEL_EXPLICAT.md` — explicație completă set + alegere XGBoost + 22 surse verificate.
  - `reference_dataset/DATASHEET.md` — datasheet Gebru, RECONCILIAT la v1.1 în sesiune.
  - `Roluri_si_actori_set_audit.docx`, `Profiluri_atac_MITRE.docx` (rădăcină) — tabele actori + mapare MITRE.
  - `runtime_ids/docs/EVALUARE_EXTERNA_SI_REMEDII.md` — raportul de evaluare externă (vezi §5).

## 4. Performanța modelului de Audit (XGBoost, `models/audit_api_xgb/`)
- Pe test sesiune-disjunct (15 trăsături): precision 0.806, **recall 0.996**, F1 0.891, **FPR 2.7%**, ROC-AUC 0.999.
- Importanță trăsături: **n_list 0.336**, n_selfreview 0.259, n_secrets 0.090…
- Servit prin **Booster API** (nu wrapper sklearn — bug save/load XGBoost 2.x). Histerezis K (episod = alertă dacă ≥K ferestre).

## 5. EVALUAREA EXTERNĂ (anti-circularitate) — ce s-a făcut și ce a ieșit
Motivație: atacurile sintetice sunt scriptate de aceeași persoană care etichetează → risc ca modelul să învețe *scriptul/artefactul*, nu *tehnica*. Validare cu **unelte de atac terțe**, sub identități dedicate, capturate în kube-audit, scorate cu modelul.

**Unelte (status):**
| Unealtă | Producător | Clasă | Status |
|---|---|---|---|
| Stratus Red Team | DataDog | escaladare/credential-access | ✅ instalat (binar darwin), folosit |
| rakkess (`kubectl access-matrix`) | krew/Cornelius Weig | recon (can-i) | ✅ instalat via **krew** (oficial krew-index) |
| kdigger | Quarkslab | recon | ⚠️ instalat; bucket `authorization` n-a generat `can-i` capturabil |
| Peirates | InGuardians | lanț real atac / escaladare | ✅ **RULAT held-out** în pod (v1.2) — escaladare detectată 100% (vezi §9) |
| MKAT, KubeHound | DataDog | enumerare/recon | binare disponibile, nefolosite |
| rakkess binar standalone, kube-hunter | — | — | indisponibil / off-API (nepotrivit) |

**Findings majore (toate oneste, reproductibile):**
1. **Escaladare (Stratus):** model neschimbat → recall pe **fereastră 4.1%** (vs 100% sintetic), dar **episod DETECTAT**. Cauză: modelul a învățat **densitatea** scripturilor (n_secrets 6.4 sintetic vs 0.27 Stratus), nu tehnica.
2. **Reguli de remediu:** baseline + regula cumulativă **B** dau fals-pozitiv pe operatori benigni; **overlay de severitate F** (primitive rare: exec/cluster-admin binding + lățime) → recall 100% & FPR 0%. F prinde și Stratus (100%) acolo unde modelul antrenat (A+D) nu generalizează.
3. **A+D (POC):** trăsături invariante la densitate + tempo variat → ajută în distribuția proprie, **dar NU generalizează la unealta externă** (Stratus 0% la episod pe modelul A+D). → e nevoie de strat hibrid (ML + reguli F).
4. **Recon (rakkess, can-i real):** rakkess a generat **2810 can-i** (n_selfreview 17.31, 2× sintetic), dar modelul de producție → **recall 0.8%**. Cauză: modelul detectează reconul prin **n_list** (artefact al scriptului recon-sa), nu prin can-i. Reconul sintetic 98.7% era **artefactual**.
5. **Fix recon (experiment cu can-i benign în mix):** adăugarea de can-i pur în train **închide recall-ul** (12.5%→95.7% pe rakkess) **DAR explodează FPR-ul pe can-i benign** (54%→93%). → **limită fundamentală**: recon-`can-i` ≈ automatizare-`can-i` benignă (identice la audit). Fix real = **allowlist de identități + anomalie de rată**, NU clasificare comportamentală.

**Concluzia de fond:** ambele cifre sintetice mari (escaladare 100%, recon 98.7%) erau **optimiste/artefactuale**; validarea externă le-a expus. Sistemul robust e **hibrid**: model ML + overlay de severitate (F) pe escaladare; allowlist+rată pe recon.

## 6. Tool-disjunct (design pt. A+D corect, lucru viitor)
- **TRAIN** pe o unealtă (ex. Stratus + tempo variat sintetic) → **HELD-OUT TEST** pe **altă** unealtă (ex. Peirates). Unealta de train ≠ de test (analog disjuncției spațiale TESSERACT).
- Constrângere actuală: pe can-i nu există a doua unealtă terță curată (rakkess = canonică, ținută eval; kdigger eșuat). Pt escaladare: Stratus(eval) + Peirates(train) = fezabil.

## 7. Stare curentă + de făcut
- Clusterul **rulează** (cost) — de oprit cu `az aks stop` când nu se lucrează.
- **SET v1.2 CONSTRUIT și persistat** (`reference_dataset_v2/ref_v2_all.csv` + `DATASHEET.md`) — vezi §9. Pipeline-ul (`train_v2.py`) e reproductibil din CSV.
- Artefacte de atac Peirates (CRB-uri cluster-admin, SA/pod atacator) **curățate** după colectare.
- Scripturi experiment vechi (efemere, `/tmp`): `detonate.sh`, `score_external.py`, `recon_fix2.py` etc. — de re-creat din §5 dacă e nevoie. Scripturile v1.2 sunt **persistate** în `collect/`.
- De făcut (opțional): scală mai mare pentru held-out (mai multe episoade Peirates pt CI strâns); a doua unealtă de recon held-out; integrare overlay F + allowlist în serving-ul live (`ids-audit-xgb`).

## 9. SET v1.2 — pipeline hibrid + held-out tool-disjunct (CONSTRUIT, 2026-06-07)
Iterația care **remediază** findings-urile din §5. Artefact: `reference_dataset_v2/ref_v2_all.csv` (**22 422 ferestre**, **13 sesiuni**). Pipeline: `train_v2.py`. Featurizer: `export_v2.py`. Datasheet: `reference_dataset_v2/DATASHEET.md`.

**Cele 3 remedii aplicate:**
- **(A) 29 trăsături invariante la densitate** (15 vechi + 14 noi: prezență/rată/lățime/severitate/cumulativ pe actor) — contra overfitting-ului pe densitate (finding §5.1).
- **(D) split tool-disjunct:** TRAIN = sintetic (tempo variat) + **Stratus** (escaladare); HELD-OUT = **Peirates** (escaladare) + **rakkess** (recon). Analog disjuncției spațiale TESSERACT.
- **(F) overlay de severitate** pe episod (creare CRB / exec / secrete în ≥2 ns) + **recon = allowlist+rată** (NU clasificator) — contra ambiguității recon-`can-i` (finding §5.5).

**Rezultate (episod, split tool-disjunct):**
| Categorie | clasif | F | clasif+F | recon allow+rată |
|---|:--:|:--:|:--:|:--:|
| ESCALADARE test sintetic | 100% (3) | 67% | **100%** | 0% |
| **ESCALADARE held-out Peirates** | **100%** (1) | **100%** | **100%** | 0% |
| RECON sintetic (recon-sa) | 0% (corect) | 0% | 0% | **100%** (1) |
| RECON held-out (rakkess) | 100% (3) | 0% | 100% | **100%** (3) |
| BENIGN can-i | 0% (4) | 0% | 0% | **0%** |
| BENIGN normal | 0% (78) | 4% | 4% | 0% |

**Ce demonstrează (vs §5):** (1) **generalizare tool-disjunctă** — clasificatorul antrenat pe sintetic+Stratus detectează **Peirates nevăzut 100%** (window-level: 23/23 has_secret, 22/23 severity≥2, secrete în 5 ns) → adresează circularitatea. (2) **recon rezolvat onest** — v1.1 dădea rakkess 0.8%; v1.2 prin allowlist+rată prinde recon-sa+rakkess 100% cu **0% FP pe can-i benign**. **Caveat:** N mic (Peirates 1 episod/23 ferestre); Stratus doar 21 ferestre train; identitate allowlistată compromisă ce face recon ar scăpa.

**Scripturi v1.2 (persistate):** `export_v2.py`, `train_v2.py`, `tool_collect_v2.sh`, `peirates_collect.sh` (driver: O comandă/invocare Peirates — readline-ul lui se blochează pe DSR în PTY și desincronizează pe stdin multi-linie; necesită `kubectl` linux în pod), `setup_actors.sh`, `scale_collect.sh` (OUT env-overridable).

### §9.1 REDESIGN ONEST v1.3 (post-verificare adversarială, 2026-06-07)
O verificare adversarială (workflow-uri cu mai mulți auditori care au reprodus cifrele) a arătat că rezultatele v1.2 erau **umflate de construcția testului**. v1.3 remediază 4 probleme și **sacrifică cifrele optimiste pentru cifre held-out reale**. Artefact: `ref_v2_all.csv` (**23 306 ferestre, 14 sesiuni**). Pipeline canonic: `train_v2.py` (acum **A_minus_nlist**). Ablație regimuri: `eval_v2_clean.py` → `EVAL_REDESIGN_V2.md`. Datasheet: `reference_dataset_v2/DATASHEET.md` (CHANGELOG v1.3).
- **Dedup** (88% ferestre escaladare test erau byte-identice cu train → 176 vectori distincți din 362).
- **Stratus mutat în held-out** + **identitate atacator NOUĂ** `adversary-stealth` (sesiunea 14) → held-out attacker+tool-disjunct pe 3 regimuri de densitate: **dens (Peirates) / rar (Stratus) / DILUAT (lowslow)**.
- **`n_list` SCOS** (cârjă de densitate: model învăța „atac⟺listează mult", median 14; atac diluat n_list=0 → ratat). A_minus_nlist (28) domină; modelul se sprijină pe `has_secret` (imp 0.57). Eliminări mai agresive → FPR 8–20%.
- **Atac DILUAT** (lowslow, 119 ferestre): densitate mică (n_secrets 0.34, n_list 0) + primitivă prezentă (has_crb 45%, severity 2) → **testul lipsă pt F**.
- **F CUANTIFICAT:** +52pp Stratus rar, +55pp diluat (window), cost FP +1.1pp → plasă de siguranță pt densitate mică, demonstrată. Pe episod, clasif+F prinde escaladarea pe toate regimurile (diluat 100%) exceptând 1 episod Stratus fără primitivă periculoasă (absență de semnal).
- **rakkess „86%" = artefact** instabil (n_list×Stratus-in-train); cade la 0% la orice schimbare → modelul NU face recon; reconul = exclusiv detectorul allowlist+rată.
- **Caveat onest:** N held-out mic (lowslow=1 episod/1 identitate); diluat model-singur 36% determinist (44–64% cu subsampling); posibilă circularitate F (severity din aceleași primitive); FPR doar pe benign sintetic.
- **Scripturi noi v1.3:** `attack_lowslow.sh` (atac diluat, identitate nouă, bash 3.2-safe), `eval_v2_clean.py` (dedup + 3 regimuri × 4 seturi trăsături), `eval_model_only.py` (ablație model-singur vs pipeline → `EVAL_MODEL_VS_PIPELINE.md`).

### §9.2 ACOPERIRE MITRE EXTINSĂ v1.4 (2026-06-07)
Evaluare de suficiență (workflow, 3 lentile: MITRE + literatură + examinator) → verdict: defensabil ca **„dataset de REFERINȚĂ"** (nu benchmark), nișă genuin neacoperită public. Acoperirea era ~48% (lipsă Persistence/Defense Evasion/Impact/Lateral). v1.4 închide 3 goluri. Set acum **24 264 ferestre, 17 sesiuni, 31 trăsături**.
- **3 scenarii noi held-out** (identități atacator NOI, attacker-disjunct, pe ns scratch `lab-victim`): **IMPACT** (`adversary-impact`: delete masiv + miner), **DEFENSE EVASION** (`adversary-evasion`: delete events/webhook/networkpolicy/CRB propriu), **LATERAL** (`adversary-lateral`: impersonare `kubectl --as` + exec cross-ns). Script: `attack_gaps.sh` (sigur: scratch ns + decoy + webhook failurePolicy=Ignore + cleanup complet).
- **2 trăsături NOI** (impersonare): `has_impersonation` + `n_distinct_impersonated`. Featurizer-ul captează acum user REAL + impersonatedUser și **cheia ferestrei = atacatorul real** (înainte colapsa pe victimă). `severity += 2·has_impersonation`; F include `has_impersonation`. **Verificare:** trăsătura e specifică (0 FP) dar NU cauzală pt clasificator (TRAIN n-are impersonare → importanță 0). Am adăugat **episod de impersonare PURĂ** (ses.18, `adversary-lateral2`, `attack_lateral_pure.sh`) → ablație dovedește că `has_impersonation` e NECESARĂ pt F (pe episodul pur: F fără termen=RATEAZĂ, F cu el=PRINDE). Lateral acum **N=2 episoade**. Set = **24 365 ferestre, 18 sesiuni**.
- **Detector NOU `destruct`** (al 4-lea): identitate ne-allowlistată cu `n_delete≥5` = distructiv (0% FP benign).
- **Hibrid = 4 detectoare → 5 tactici**: clasificator (escaladare+lateral), F (flagrant+impersonare), recon (allowlist+rată can-i), destruct (allowlist+rată delete). FULL hibrid **100% pe tot exc Stratus rar 67%**, FP benign 4%.
- **Matrice MITRE** completă în `DATASHEET.md` (CHANGELOG v1.4). **Onest:** Impact/Evasion prinse de REGULI nu ML; N=1/scenariu; allowlistat compromis scapă; **Persistence** rămâne golul principal.

### §9.3 ML-CENTRIC v1.5 (2026-06-08) — ML să prindă cât mai multe + verificare dură
Cerut: mutăm detecția din reguli în ML. Colectat **mai multe episoade variate/clasă** (9 sesiuni noi, 19-27; 5 lateral/4 impact/4 evasion, identități distincte) → split **pe identitate** → clasificator antrenat pe escaladare+lateral+impact+evasion. Set: **26 009 ferestre, 27 sesiuni**. Pipeline canonic `train_v2.py` acum ML-centric. Diagnostice: `eval_ml_coverage.py`, `eval_fp_diagnostic.py`.
- **Rezultat (episod):** clasif held-out lateral 2/2, impact 4/4, evasion 1/2 (+destruct→2/2); escaladare Peirates/lowslow 100%, **Stratus-rar 0%** (F-67%); recon doar regulă. **FULL 100% exc Stratus-rar; FP benign-normal 4%.**
- **Diagnostic FP (v1.3 + câte o clasă):** FP venea **exclusiv din IMPACT**, și NU din ștergere ci din **semnalul de CREARE al minerului** (prindea crearea benignă de noduri AKS). **Fix:** impact antrenat **doar pe ștergere** (`train_v2.py`: skip ferestre impact cu `n_create>0`) → **FP 5%→0% clasif, 9%→4% FULL**, held-out 4/4 neschimbat.
- **VERDICT VERIFICARE (PARTIAL, dovadă asimetrică) — CITEȘTE înainte de a scrie în teză:** split CURAT (0 leakage identitate), FP acceptabil; DAR „ML prinde 4 tactici" e **supraevaluat**. Tare doar pt **escaladare tool-disjunctă** (Peirates/lowslow), și chiar acolo clasif cade pe **Stratus-rar** (F salvează). Pt lateral/impact/evasion held-out e **identity-disjunct sintetic** (același autor/șablon, distribuții cvasi-identice): **lateral ≈ regula has_impersonation**, **impact imp-3 40% byte-identic** (dovada → imp-2), **evasion fragil** (cade la diferență comportamentală). **N=2-4, Wilson95 LB 34-51% → „100%" nestatistic.** Formulare onestă: ML dovedit doar pt escaladare; restul = recunoaștere identity-disjunctă, nu generalizare pe tehnică independentă.
- **De întărit (lucru viitor):** held-out tool-disjunct/autor-disjunct pt lateral/impact/evasion (unelte externe reale, dacă există); mai multe episoade GENUIN variate; raportare Wilson LB lângă fiecare cifră.

### §9.4 v1.6 — regula hijack + Persistence extern + fix allowlist (2026-06-08)
**RAPORT CONSOLIDAT gata de teză: `runtime_ids/docs/RAPORT_FINAL_IDS_AUDIT.md`** (citește-l primul). Set final: **26 105 ferestre, 28 sesiuni, 32 trăsături**. Pipeline = clasificator + **4 reguli de suport** (F/recon/destruct/hijack).
- **Regula `hijack`** (`n_create_workload≥1` ne-allowlistat) prinde cazul scos din ML (miner Impact) + Stratus privileged-pod; trăsătura `n_create_workload` e DOAR pt regulă (exclusă din clasificator); 0% FP pe set. Script: `attack_persistence_stratus.sh` adaugă Persistence.
- **Persistence extern (Stratus):** clasificator **0%** (tactică nouă), prins 100% de reguli (F via has_crb, recon via can-i) → validează defense-in-depth. N=1.
- **Fix allowlist** (user complet, nu uid scurt): benign FP 11%→4%, hijack 7%→0%, 0 regresii.
- **Verificare:** hijack corect (0 FP set, fragil producție); persistence onest (reguli, nu ML); allowlist fix corect (0/22 atacatori exonerați greșit). Caveat: hijack/persistence/allowlist au riscuri de producție documentate în RAPORT_FINAL §6.4.
- **STARE FINALĂ:** pipeline-ul prinde toate tacticile held-out 100% (FP 4%), DAR onest: ML dovedit tool-disjunct doar pt escaladare; restul = identity-disjunct sintetic / reguli. Vezi RAPORT_FINAL §6-7 pt formularea defensabilă.

### §9.5 v1.7 — test lateral EXTERN + cercetare unelte (2026-06-08)
Set: **28 584 ferestre, 29 sesiuni**. (1) **Cercetare deep-research** (`UNELTE_EXTERNE_VALIDARE.md`, citat): **NU există** unealtă externă pt Impact/Defense-Evasion pe audit K8s (scripturile proprii justificate); pt Lateral doar token-reuse (Peirates/Stratus), NU impersonare. (2) **Test lateral EXTERN** (`attack_lateral_stratus.sh`, Stratus steal-token+create-token, tag=lateralext): **clasificator 0%**, prins de reguli (F via has_exec, recon, hijack). Al 2-lea test extern (după Persistence) cu ACELAȘI pattern: **pe unelte externe ML cedează (0%), regulile salvează** → validează defense-in-depth de 2 ori. Caveat: regulile prind prin efecte-secundare (exec/pod-create ale Stratus), nu „înțelegând" token-reuse.

### §9.6 v1.8 — Impact regenerat cu variație (2026-06-08)
Răspuns la întrebarea de calitate (de ce ștergerea clonei `imp-3` NU e curățare bună): **NU șterge, regenerează cu variație**. Set: **29 491 ferestre, 31 sesiuni**. **Clasa IMPACT regenerată** (`attack_impact_varied.sh`): 6 profile distincte pe trăsăturile modelului — TRAIN burst/multi-tip/miner, HELD-OUT interleaved/churn/nuke (comportamental DIFERIT). Vechiul templat (adversary-impact/imp-1/2/3) scos (sesiuni 15/22/23/24 eliminate; 40 phantom dropped de pipeline). **Byte-identic held-out↔train 40%→14%.** **Număr ONEST: clasif impact 67%** (era umflat la 100% de clona imp-3); destruct acoperă → FULL 100%. Restul tabelului neschimbat (FP 4%). Lecție: redundanța de șablon se repară prin variație de comportament, nu prin ștergerea cazului.

### §9.7 v1.9 — Escaladare + Evasion regenerate cu variație (2026-06-08)
Audit de diversitate pe TOATE clasele a găsit: escaladare in-dist 88% byte-identic (templat), evasion 23% diversitate. **Regenerate** (`attack_esc_eva_varied.sh`, tag escaladare=`escv`, evasion=`adversary-evav-*`): 6+6 profile distincte, split pe identitate, held-out comportamental diferit. Vechiul evasion scos (sesiuni 16/25/26/27). Set: **29 948 ferestre, 39 sesiuni**. **Toate clasele sintetice acum variate** (diversitate escaladare 88%/lateral 94%/evasion 75%/impact 67%; overlap held-out ≤14%). **Număr ONEST escaladare variat: clasif 67%** (testul templat dădea 100% iluzoriu). **Efect pozitiv:** profilul escv-3 (rbac-create) → clasificatorul a învățat CRB-create=atac → **Persistence 0%→100% la clasificator** (generalizare reală), cost +1pp FP benign (FULL 5%). Toate numerele de detecție reflectă acum generalizare, nu clone.

### §9.8 Model de PRODUCȚIE salvat + serving live actualizat (2026-06-08)
- **Dataset:** `runtime_ids/deploy/azure/collect/reference_dataset_v2/ref_v2_all.csv` (29 948 ferestre) + `sessions.txt` + `DATASHEET.md`.
- **Model de PRODUCȚIE** (`train_production.py` → `runtime_ids/models/audit_hybrid_v2/`): `classifier.json` (antrenat pe TOATE datele, 4077 ferestre dedup, recon+miner excluse) + `pipeline_config.json` (30 trăsături + praguri reguli R_RECON/D_DEL/H_WL/K + allowlist) + `feature_importance.json`. Distinct de modelul de EVALUARE (train_v2.py, held-out) — generalizarea se raportează din train_v2; producția = acoperire maximă pt serving.
- **Serving live ACTUALIZAT** la v1.9 hibrid: `runtime_ids/service/audit_xgb_service.py` rescris (30 trăsături + 4 reguli F/recon/destruct/hijack + allowlist, oglindește export_v2). Deployment `ids-audit-xgb` (ns runtime-ids) redeployat: ConfigMap `audit-xgb-code` recreat cu cod+classifier.json+pipeline_config.json (NB: `kubectl create`, nu `apply` — classifier.json 316KB depășește limita de adnotare a apply-ului). Manifest `11-audit-xgb.yaml` env: `RUNTIME_IDS_XGB_MODEL=/app/xgb/classifier.json`. Verificat: healthz=1.9-hybrid, escaladare→[clasificator,F], benign-allowlistat→fără alertă. `/predict/raw` ia acum `{"user":..., "events":[{verb,resource,sub,ns,code,decision,imp}]}`.
- Modelul VECHI `models/audit_api_xgb/model.json` (v1.1, 15 trăsături) = stale, înlocuit de `audit_hybrid_v2/`.

### §9.9 v2.0 — hardening SRE + allowlist ancorat + N mărit/Wilson (raspuns la plafonul 7.0)
Set: **36 926 ferestre, 56 sesiuni**. Trei atacuri la plafonul de 7.0 din dezbatere:
- **Allowlist ANCORAT** (exact + prefix namespace, NU substring) în train_v2/train_production/serving — identic, fără skew. Bypass eliminat (default:adversary-*, sre-oncall-evil NU mai exonerate); 0 atacatori exonerați, FP neschimbat.
- **SRE hardening** (`11-audit-xgb.yaml`): replicas=2 + PDB, securityContext (runAsNonRoot/readOnlyRootFS/drop ALL caps/seccomp), NetworkPolicy. IaC: `Dockerfile.audit` (imagine versionată) + `deploy_audit_hybrid.sh` (server-side apply). Deployat live (2 replici Running, verificat healthz + securityContext efectiv).
- **N held-out mărit** (`attack_more_episodes.sh`, +17 episoade): Stratus 3→8, lateral 2→5, impact 3→6, evasion 3→6, lowslow 1→4. **Wilson 95% LB 34-51% → 51-68%** (Stratus tool-disjunct 68%). train_v2 IMP_HO/LAT_HO/EVA_HO extinse cu noile identități.
- **Split tool-disjunct CONFIRMAT ZERO contaminare** (concern train/test al utilizatorului): escaladarea trainează DOAR pe sintetic; TOATE uneltele externe (Stratus/Peirates/lowslow/rakkess/persistence/lateralext) held-out. Verificat: 0 ferestre unealtă externă în train. (Design mai tare decât „Stratus train/Peirates test" — clasificatorul nu vede nicio unealtă.)
- FULL hibrid 100% pe toate categoriile held-out; benign-normal FP **7%** (de la 5%, costul antrenării mai agresive). Datasheet CHANGELOG v2.0.

### §9.10 GitOps drift REZOLVAT (2026-06-08) — cale unică imuabilă+hardenată
Atac la plafonul „hardening și imutabilitate se exclud". **Imagine imuabilă construită + pushată: `andreeagrigore/runtime-ids-audit:1.9`** (Dockerfile.audit, cod+model+config copt; Docker Hub, clusterul trage din același cont ca baza). Manifest CANONIC unic `k8s/11-audit-xgb.yaml` = imagine imuabilă **ȘI** hardening complet (replicas=2 + **podAntiAffinity** noduri diferite + PDB + securityContext + **NetworkPolicy strict** runtime-ids/monitoring). Manifestul-imagine redundant șters; cfgmap mutat în `11-audit-xgb-cfgmap-fallback.yaml` (același pod-spec hardenat → zero drift). `deploy_audit_hybrid.sh` MODE=image (canonic, implicit) / cfgmap (fallback). **Deployat LIVE + verificat:** 2 poduri Running pe noduri DIFERITE (vmss000000+000001), image=1.9, healthz=1.9-hybrid. NB: imaginea e amd64 (build `--platform linux/amd64`, noduri AKS amd64). ⚠️ **NU re-deployat încă cu v2.1** (cod serving + model nou) — vezi §9.11; necesită rebuild imagine `:2.1` + redeploy.

### §9.11 v2.1 — N la prag Wilson ≥70% + regula `persist` + fix calibrare FP (2026-06-08)
Set: **49 424 ferestre, 101 sesiuni, 34 trăsături** (`attack_wilson_push.sh`, +45 episoade cu VARIAȚIE genuină — module Stratus rotite, profile sintetice variate, NU clone). Cap Wilson LB ridicat:
- **N ≥10/categorie → raportare naivă „6 categorii ≥70%" — CORECTATĂ după audit ML (runda 5).** Auditul a expus N umflat de traiectorii byte-identice + leakage la nivel de fereastră (dedup doar train). FIX în `train_v2.py`: `catsig` (dedup traiectorii → N distinct: lowslow 10→5, lateralext 6→3, Stratus 15→11) + `ep_class_novel`/`TRAINPOS` (metrica `FULL_nov` pe ferestre nevăzute). **Wilson95 LB strict (FULL_nov, N distinct): DOAR 2 categorii ≥70%** — lateral 70% (N=9) + persistence 70% (N=9); restul evasion 60/lowslow 57/impact 56/Stratus 52/recon 51/escv 45/lateralext 44/Peirates 21. FP benign 2%. Pentru ≥70% riguros pe toate ar trebui ~12-15 episoade GENUIN distincte/clasă.
- **Regula nouă `persist`** (2 trăsături `has_csr`/`has_tokenreq`, rule-only): diversificarea modulelor Stratus a EXPUS că persistence era prins doar 56% (`create-client-certificate`/CSR și `create-token`/TokenRequest evadau). Regula (identitate NE-allowlistată cu CSR self-approve / TokenRequest) → **persistence 56%→100%, LB 27%→70%, ZERO FP** (tot benign cu CSR/token e control-plane allowlistat: kubelet/aksService/certificate-controller — verificat 0 ne-allowlistate). Oglindit în export_v2/train_v2/train_production/audit_xgb_service (5 reguli, 34 features).
- **FINDING ONEST — Stratus escaladare 100%→80% (LB 55%):** cu module diverse (`hostpath-volume`/`nodes-proxy` adăugate), 3/15 episoade ratate fac DOAR enumerare de noduri (`list nodes`/node-proxy) → niciun semnal distinct de benign. Raportat explicit ca limită (nu revenit la modulele ușoare).
- **FIX calibrare FP:** benign incidental din sesiunile noi umflase `scale_pos_weight` 10.75→13.27 → FP benign 7%→**39%**. Reparat: `SPW_CAP=11` (punct operare validat v2.0, env-override în train_v2) → **FP 4%**, recall held-out neschimbat. train_production: `spw=min(11,...)` (natural 5.62 < cap, deci nelegat).
- **Model producție regenerat** (`models/audit_hybrid_v2/`): 5724 ferestre, 865 atac/4859 benign, config 5 reguli + 34 features. Serving smoke-test OK (CSR ne-allowlistat→persist; cert-manager→nimic). Datasheet CHANGELOG v2.1, RAPORT §5/§6.2 actualizate.

### §9.12 v2.2 — rigoare ML (split feature-disjunct + Wilson dublu) + regula `anom` + digest-pin (2026-06-08)
Răspuns la findings-urile rundei 6 (toate 4). Set: **50 513 ferestre, 107 sesiuni** (`attack_compromised_allowlist.sh`, +6 episoade kube-system compromis). Dezbatere: runda 6 = 8.03.
- **ML #1+#2:** **split train FEATURE-disjunct** (`EVALVECS` exclude din train ferestrele de atac byte-identice cu eval → leakage reparat la SURSĂ, nu mascat) + **Wilson DUBLU** în `train_v2.py`: **W(clasif)**=podea ML PURĂ, **W(FULL)**=podea hibridă. Onest brutal: ML PUR cade **0% pe TOATE tacticile externe** (Stratus/persistence/lateralext/recon); doar lateral 70% + persistence 70% ating LB≥70% (pe ambele baze). FP benign 2% (0% clasif).
- **SECURITATE #4 — regula `anom`** (`attack_compromised_allowlist.sh`: SA fabricat în kube-system `compromised-ctrl-N`, allowlistat-prin-prefix, tactici rate-based pure). GAP demonstrat: evadează regulile gated. Analiză empirică: regula de RATĂ pură NU merge (controllerele benigne fac mass-delete/token la rate ≥ atac: `n_delete` benign max 14 ≥ atac 12). Semnal discriminant = identitate **NECUNOSCUTĂ**. `ep_anom` = allowlistat-prin-prefix DAR ∉ `KNOWN_ALLOW` (41 identități benigne observate) + rată privilegiată → **prinde 100% (6/6), 0 FP**. Reziduu onest: controller EXISTENT compromis (token furat, ∈ known_allow) → profil per-identitate (lucru viitor). Oglindit complet: export_v2 (tag `compromised`), train_v2, train_production (config `known_allow` + regula anom), audit_xgb_service (6 reguli). Serving smoke-test + test LIVE OK.
- **DevOps #3 — digest-pin:** imagine live pin-uită prin **`@sha256`** (imutabilitate REALĂ, nu tag mutabil) + provenance reparat (config version v2.2-hybrid, IMG default, docstring, comentariu manifest). Build+push `:2.2`, deployat LIVE digest-pinned (`andreeagrigore/runtime-ids-audit:2.2@sha256:8e43069ba84998a30fde55741a08c0452bb14cf5aa34d3c96ce10e2b822b22d4`), 2 poduri Running noduri diferite, healthz v2.2-hybrid 6 reguli, test live anom OK. Digest istoric: :2.1.1 = sha256:d5d7d0db...
- Pipeline canonic acum: clasificator + **6 reguli** (F/recon/destruct/hijack/persist/**anom**). Set tags: ...+`compromised` (kube-system compromis).

## 8. Surse externe verificate (de citat)
Sharafaldin 2018 (CICIDS2017), Moustafa 2015 (UNSW-NB15), Engelen 2021 / Lanvin 2022 (critici CICIDS), Arp 2022 (Dos&Don'ts), Pendlebury 2019 (TESSERACT), Sommer&Paxson 2010, Grinsztajn 2022 / Shwartz-Ziv 2022 (GBDT vs DL tabular), Gebru 2021 (Datasheets), Franzil 2026 (K8NTEXT), Sever&Dogan 2023 (ITU K8s), MITRE ATT&CK Containers, NSA/CISA 2022, Falco. Unelte: Stratus (DataDog), Peirates (InGuardians), rakkess (krew-index), kdigger (Quarkslab).
