# Datasheet — K8S-APIAUDIT-IDS v2.2

> **Versiune 2.2** · 2026-06-08. Set `ref_v2_all.csv` (**50 513 ferestre, 107 sesiuni, 34 trăsături**). Pipeline
> `train_v2.py`: clasificator (escaladare+lateral+impact+evasion) + **6 reguli** (F/recon/destruct/hijack/persist/**anom**).
> **Raport consolidat gata de teză: `runtime_ids/docs/RAPORT_FINAL_IDS_AUDIT.md`.**

## CHANGELOG v2.2 (rigoare statistică + regula `anom` granița de încredere + digest-pin — supersedează v2.1)

Răspuns la auditul experților (rundele 5-6):
- **[ML — rigoare]** **Split train FEATURE-disjunct** (exclude din train ferestrele de atac byte-identice cu eval → leakage
  reparat la sursă, nu mascat) + **dedup TRAIECTORII** pentru N (Wilson cere trials independente) + **Wilson DUBLU**:
  W(clasif)=podeaua ML PURĂ, W(FULL)=podeaua hibridă. Onest: **ML pur cade ~0% pe TOATE tacticile externe**; doar
  lateral+persistence ating LB ≥70%. FP benign 2%.
- **[SECURITATE — regula `anom`]** Atac NOU colectat: **identitate kube-system COMPROMISĂ** (SA fabricat, allowlistat-prin-prefix).
  Demonstrează gaura granitei de încredere (evadează regulile gated). Analiza empirică: regula de rată pură NU merge
  (controllerele benigne fac mass-delete/token la rate ≥ atac). Fix: `anom` = allowlistat-prin-prefix DAR ∉ `known_allow`
  (41 identități benigne observate) + rată privilegiată → **prinde 100%, 0 FP**. Reziduu: controller existent compromis (token furat).
- **[DevOps — digest-pin]** Imagine live pin-uită prin **`@sha256`** (imutabilitate REALĂ runtime, nu doar tag) + provenance
  reparat (config version, IMG default, docstring). Deployat live `:2.2@sha256:8e43069b`, healthz v2.2-hybrid, 6 reguli.

## CHANGELOG v2.1 (N mărit + regula `persist` + fix calibrare FP — supersedată de v2.2)

Răspuns la cerința de a ridica Wilson LB peste pragul de 70% (+45 episoade noi, total 101 sesiuni):
- **[ML] N mărit + Wilson LB RIGUROS (corectat după audit ML):** colectare +45 episoade. Raportarea naivă („6 categorii
  la 72%") s-a dovedit optimistă — un audit a expus (a) **N umflat de traiectorii byte-identice** (module Stratus reluate;
  lowslow/lateralext prea similare) și (b) **leakage la nivel de fereastră** (dedup doar în train → 10-19% ferestre eval
  byte-identice cu train). **Fix:** dedup TRAIECTORII înainte de a număra N (lowslow 10→5, lateralext 6→3, Stratus 15→11)
  + metrica `FULL_nov` (recall pe ferestre GENUIN nevăzute). **Wilson95 LB strict (pe FULL_nov, N distinct): doar 2
  categorii ≥70%** — lateral 70% (N=9) + persistence 70% (N=9); restul 45-60%. Cifre defensabile adversarial (anti-TESSERACT).
- **[ML — regula nouă `persist`]** Diversificarea modulelor Stratus a EXPUS că persistence era prins doar parțial
  (56%): `create-client-certificate` (CSR) și `create-token` (TokenRequest) **evadau**. Adăugate 2 trăsături
  (`has_csr`, `has_tokenreq`) + regula `persist` (identitate NE-allowlistată cu CSR/TokenRequest). **Persistence
  56%→100%, Wilson LB 27%→70%**, **ZERO cost FP** (2128 ferestre benigne cu CSR/token sunt TOATE allowlistate:
  kubelet/aksService/certificate-controller). Trăsăturile sunt **rule-only** (excluse din clasificator).
- **[FINDING ONEST — Stratus escaladare 100%→80%]** Cu module diverse (am adăugat `hostpath-volume`, `nodes-proxy`),
  recall-ul real e **80% (12/15), Wilson LB 55%** — nu 100% ca pe subsetul îngust anterior. Cele 3 ratate fac DOAR
  enumerare de noduri (`list nodes`/node-proxy), fără secret/RBAC/workload/CSR/token → niciun semnal distinct de
  benign. Limită apărabilă, **raportată explicit** (nu ascunsă prin revenirea la module ușoare).
- **[FIX calibrare FP]** Benign-ul incidental din sesiunile noi a umflat `scale_pos_weight` 10.75→13.27 → FP
  benign-normal sărise la **39%**. **Reparat**: cap `spw≤11` (punctul de operare validat în v2.0) → **FP înapoi la 4%**,
  recall held-out neschimbat. Agresivitatea modelului nu mai depinde de cât benign incidental s-a colectat.
- **[serving oglindit]** `audit_xgb_service.py`: 34 trăsături (cu `has_csr`/`has_tokenreq`) + 5 reguli (cu `persist`).
  `train_production.py`: spw cap + config 5 reguli. Verificat: atac CSR ne-allowlistat → `persist`; cert-manager → nimic.

---

# Datasheet — K8S-APIAUDIT-IDS v2.0 (istoric)

## CHANGELOG v2.0 (hardening SRE + allowlist ancorat + N mărit/Wilson — supersedează v1.9)

Răspuns la plafonul de 7.0 din dezbaterea de experți (axa SRE + axa ML-N-mic):
- **[SECURITATE] Allowlist ANCORAT** (exact + prefix de namespace, NU substring): `allowed(u) = u in ALLOW_EXACT or
  u.startswith(ALLOW_PREFIX)`. Elimină bypass-ul (atacator în `default` sau nume `sre-oncall-evil` NU mai e exonerat).
  Verificat: 0 atacatori exonerați, acoperire benign identică, FP neschimbat. Identic în train/serving (fără skew).
- **[SRE] Hardening producție** (`11-audit-xgb.yaml`): **replicas=2 + PodDisruptionBudget** (HA), **securityContext**
  (runAsNonRoot, readOnlyRootFilesystem, drop ALL caps, seccomp RuntimeDefault, allowPrivilegeEscalation=false),
  **NetworkPolicy**. Plus **IaC GitOps-clean**: `Dockerfile.audit` (imagine versionată cu cod+model copt),
  `deploy_audit_hybrid.sh` (server-side apply, evită limita 262KB). Deployat live, verificat (2 replici Running).
- **[ML] N mărit per held-out + Wilson LB strâns** (+17 episoade): Stratus 3→**8** (tool-disjunct), lateral 2→5,
  impact 3→6, evasion 3→6, lowslow 1→4. **Wilson 95% LB: 34-51% → 51-68%** (Stratus tool-disjunct = 68%).
- **[separare train/test CONFIRMATĂ]** Escaladarea se antrenează **DOAR pe sintetic**; **TOATE uneltele externe
  (Stratus/Peirates/lowslow/rakkess/persistence/lateralext) sunt HELD-OUT** — verificat **ZERO contaminare** (0
  ferestre de unealtă externă în train). Design mai tare decât „Stratus train / Peirates test" (clasificatorul nu
  vede nicio unealtă → catch pe toate = generalizare reală).
- **Rezultat:** FULL hibrid 100% pe toate categoriile de atac held-out; FP benign-normal **7%** (ușor crescut de la
  5% — costul antrenării mai agresive pe clasele regenerate; onest raportat).

---

# Datasheet — K8S-APIAUDIT-IDS v1.9 (istoric)

## CHANGELOG v1.9 (Escaladare + Evasion regenerate cu variație — supersedează v1.8)

Audit de diversitate (vectori distincți/total + suprapunere byte-identică held-out↔train) a arătat că **escaladarea
sintetică in-dist era templată (88% byte-identic)** și **evasion repetitiv (23% diversitate)**. Regenerate cu
variație comportamentală (`attack_esc_eva_varied.sh`), 6+6 profile distincte, split pe identitate:
- **ESCALADARE variat** (tag `escv`): TRAIN forbid-trail / multi-ns-dump / rbac-create; HELD-OUT exec-focus /
  single-ns-hoard / slow-mixt. Diversitate **88%**, held-out byte-identic **3%** (era 88%). **Număr ONEST: clasif
  67%** pe held-out variat (vs 100% iluzoriu pe testul templat).
- **EVASION variat** (identități `adversary-evav-*`): npevt/whcrb/rbevt (train) vs churn/highvol/slow (held-out).
  Diversitate **75%**, overlap **3%** (era 23% div). Vechiul evasion templat scos (sesiuni 16/25/26/27).
- **Efect pozitiv:** profilul `escv-3` (rbac-create) a învățat clasificatorul că crearea de clusterrole = atac →
  **Persistence a urcat 0%→100% la clasificator** (generalizare reală pe primitiva comună CRB-create). Cost: +2pp FP
  benign (flag pe creare benignă de clusterrole), FULL benign-normal 4%→5%.
- **Toate clasele sintetice acum VARIATE** (escaladare 88% / lateral 94% / evasion 75% / impact 67% diversitate;
  overlap held-out ≤14%) → numerele de detecție reflectă generalizare reală, nu clone.

---

# Datasheet — K8S-APIAUDIT-IDS v1.8 (istoric)

## CHANGELOG v1.8 (Impact regenerat cu variație — supersedează v1.7)

- **Clasa IMPACT regenerată cu variație comportamentală GENUINĂ** (`attack_impact_varied.sh`): 6 identități cu profile
  distincte pe trăsăturile pe care le vede modelul — TRAIN: burst-1tip / multi-tip / miner; HELD-OUT (comportamental
  DIFERIT): interleaved-slow / churn / high-volume-nuke. Vechiul impact templat (adversary-impact/imp-1/2/3) **scos**
  (sesiuni 15/22/23/24 eliminate; 40 ferestre legacy-phantom excluse de pipeline prin partiția `drop`).
- **Repară redundanța de șablon** (cauza: bucla deterministă de ștergere → aceeași rampă `n_delete` la toți):
  byte-identic held-out↔train **40% → 14%**.
- **Număr ONEST de detecție:** clasificator pe impact held-out **67%** (era umflat la 100% de clona `imp-3`) —
  modelul ratează ~1/3 din comportamentele de impact cu adevărat noi; `destruct` acoperă → FULL 100%. **Lecție
  metodologică: regenerează cu variație, nu șterge cazul incomod** (răspuns la întrebarea de calitate).

---

# Datasheet — K8S-APIAUDIT-IDS v1.7 (istoric)

## CHANGELOG v1.7 (test lateral EXTERN + cercetare unelte — supersedează v1.6)

- **Test LATERAL tool-disjunct cu Stratus** (`attack_lateral_stratus.sh`, identitate `redteam-lat-ext`): module
  `steal-serviceaccount-token` + `create-token` (singurul lateral cu unealtă externă — vezi cercetarea). **Rezultat:
  clasificator 0%** (la fel ca Persistence), prins 100% de reguli (F via `has_exec`, recon via `can-i`, hijack via
  creare pod). **Al 2-lea test extern care confirmă: pe unelte genuin externe ML cedează, regulile salvează.**
- **Cercetare unelte externe** (`runtime_ids/docs/UNELTE_EXTERNE_VALIDARE.md`, deep-research citat): **NU există**
  unealtă terță pentru **Impact** și **Defense Evasion** pe planul de audit K8s → scripturile proprii sunt
  justificate. Pentru **Lateral**, unelte externe DOAR pentru token-reuse (Peirates/Stratus), NU pentru impersonare.

---

# Datasheet — K8S-APIAUDIT-IDS v1.6 (istoric)

## CHANGELOG v1.6 (regula hijack + Persistence extern + fix allowlist — supersedează v1.5)

- **Regula `hijack`** (componentă de suport, al 4-lea detector): identitate ne-allowlistată cu `n_create_workload≥1`
  = workload-hijack/cryptominer. Prinde **cazul scos din ML** (minerul Impact, exclus ca să scadă FP) + bonus
  Stratus privileged-pod. Trăsătura `n_create_workload` e folosită DOAR de regulă (exclusă din clasificator).
  **0% FP** pe benign în set. *Caveat: fragilă în producție (orice creator de workload ne-allowlistat ar da FP).*
- **Test EXTERN Persistence (Stratus Red Team):** modulele `create-admin-clusterrole/token/client-certificate`
  rulate ca held-out tool-disjunct (identitate `redteam-persist`). **Rezultat ONEST: clasificatorul ML dă 0%**
  (tactică nouă, nevăzută, prob max 0.059); prinsă **100% doar de reguli** (F via `has_crb`, recon via `can-i`).
  Validează empiric defense-in-depth: la tactică nouă, ML cedează, regulile salvează. N=1 episod.
- **Fix bug allowlist:** episoadele cheite pe uid scurt nu prindeau prefixele `system:serviceaccount:kube-system`
  → controllerele kube-system nu erau exonerate → `hijack` FP 7%. **Fix:** regulile primesc user COMPLET →
  benign-normal FP **11%→4%**, hijack **7%→0%**, **0 regresii** (0/22 atacatori exonerați greșit).
- **Verificare adversarială:** toate 3 confirmate; vezi RAPORT_FINAL §6 pentru caveat-urile complete.

---

# Datasheet — K8S-APIAUDIT-IDS v1.5 (istoric)

> Pipeline `train_v2.py` mutat **ML-CENTRIC**: clasificatorul antrenat pe escaladare + lateral + impact + evasion.

## CHANGELOG v1.5 (ML-centric + onestitate verificată — supersedează v1.4)

Obiectiv (cerut explicit): **partea de ML să prindă cât mai multe atacuri**, nu doar regulile. Am colectat **mai
multe episoade variate per clasă** (5 lateral, 4 impact, 4 evasion, identități distincte) → split **pe identitate**
(train unele identități, held-out altele) → am antrenat clasificatorul **inclusiv pe lateral/impact/evasion**.

**Rezultat (episod) — clasificatorul (ML) prinde held-out:** escaladare in-dist/Peirates/lowslow 100%, **lateral
2/2, impact 4/4, evasion 1/2** (+ destruct backup → evasion 2/2); recon doar regula (100%). **FULL hibrid 100% pe
tot, exc. Stratus-rar (67%); FPR benign-normal 4%, can-i 0%.**

**Diagnostic FP (v1.3 + câte o clasă pe rând) — a găsit și reparat sursa FP:**
- `+lateral` → **0 FP** (semnalul `has_impersonation`=0 în tot benign-ul).
- `+impact` → **+2 FP episod**, NU din ștergere ci din **semnalul de CREARE al minerului** (T1496), care prindea
  greșit crearea benignă de noduri AKS. **Fix:** clasa Impact antrenată **doar pe ferestre de ștergere** (fără
  miner-create) → **FP 2/57 → 0/57, held-out neschimbat 4/4**. (FP clasif total 5%→0%, FULL 9%→4%.)
- `+evasion` → 0 FP, dar clasificatorul singur nu generalizează (held-out 0/2 fără datele de ștergere de la impact).

### ⚠️ ONESTITATE — verificare adversarială (dovadă ASIMETRICĂ, verdict PARTIAL)
„ML prinde 4 tactici" **NU e uniform dovedit**:
- **Escaladare = singura cu dovadă TARE tool-disjunctă** (unelte externe reale: Peirates, lowslow), **DAR**
  clasificatorul **eșuează pe Stratus-rar (0/3)** — doar overlay-ul F salvează (67%). ML generalizează pe unelte
  dense, cade pe cea rară.
- **Lateral/Impact/Evasion = dovadă SLABĂ, doar IDENTITY-disjunctă** (același tool/autor/cluster/șablon):
  - distribuții train vs held-out cvasi-identice (impact `n_delete` 7.15 vs 6.51; lateral impersonated 4.73 vs 4.72);
  - **LATERAL ≈ regulă deghizată** (`has_impersonation`=0 în 14856 benign; scoaterea ei nu schimbă recall → ML nu
    bate o regulă trivială);
  - **IMPACT parțial clonă** (`imp-3` 40% byte-identic cu train, secvență `n_delete` hardcodată) → dovada curată
    se reduce la `imp-2`;
  - **EVASION fragil** — singurul held-out comportamental diferit, și acolo recall scade (clasif 1/2).
- **N catastrofal de mic** (held-out 2/4/2 episoade). **Wilson 95% LB: lateral 34%, evasion 34%, impact 51%.**
  „100%" pe N=2-4 **nu e statistic**.
- **Concluzie defensabilă:** ML aduce valoare **dovedită doar pentru escaladare** (tool-disjunct, cu gaura Stratus);
  pentru lateral/impact/evasion e **recunoaștere identity-disjunctă sintetică**, iar pt lateral/impact **nu depășește
  o regulă**. Split CURAT (0 leakage identitate) + FP acceptabil (4%) — dar a NU raporta „100% generalizare" fără
  Wilson LB și fără a marca held-out-ul ca identity-disjunct.

---

# Datasheet — K8S-APIAUDIT-IDS v1.4 (istoric)

> Set de date pentru detecția intruziunilor pe **planul operațional (API-server) al Kubernetes**, construit pe
> un cluster AKS managed real. Structură conform Gebru et al., *"Datasheets for Datasets"* (2021).
> Limbă: română. Versiune: **1.4** · Dată: 2026-06-07.
> Artefact: `ref_v2_all.csv` (24 365 ferestre, **18 sesiuni**, **31 trăsături**) · pipeline: `train_v2.py`
> (A_minus_nlist + 4 detectoare) · ablații: `eval_v2_clean.py`, `eval_model_only.py` · featurizer: `export_v2.py`.

---

## CHANGELOG v1.4 (acoperire MITRE extinsă — supersedează v1.3)

v1.3 acoperea bine jumătatea „post-exploatare" (Discovery/Credential Access/Privilege Escalation/Execution) dar
avea goluri pe Persistence/Defense Evasion/Impact/Lateral Movement. v1.4 închide 3 dintre cele mai importante,
toate **held-out, sub identități atacator NOI** (attacker-disjunct), pe `lab-victim` (namespace scratch + decoy,
zero risc pt cluster):

- **LATERAL MOVEMENT / Impersonation (T1134)** — `adversary-lateral`: `kubectl --as=<SA privilegiat>` + exec
  cross-namespace. **2 trăsături NOI:** `has_impersonation` (atacatorul real ≠ identitatea efectivă) +
  `n_distinct_impersonated`. Featurizer-ul captează acum **AMBELE** identități (real `user.username` +
  `impersonatedUser.username`) și **cheia ferestrei = atacatorul REAL** (înainte se colapsa pe victimă →
  impersonarea era invizibilă). `severity += 2·has_impersonation`; overlay-ul F include acum `has_impersonation`.
- **IMPACT (T1485/T1496)** — `adversary-impact`: ștergere masivă (deployments/secrets/configmaps) + workload-hijack
  (Deployment „crypto-miner" cu replici). Semnal: `n_delete` mare.
- **DEFENSE EVASION (T1070)** — `adversary-evasion`: delete Events + NetworkPolicies + ValidatingWebhookConfiguration
  (admission) + ștergerea propriului ClusterRoleBinding (cover tracks). Semnal: `n_delete` mare pe resurse de apărare.
- **Detector NOU `destruct`** (al 4-lea): identitate **ne-allowlistată** cu `n_delete≥5` pe fereastră = distructiv.
  Calibrare: benign ne-allowlistat are `n_delete` max=0 (0 declanșări); controllerele care șterg legitim sunt
  allowlistate (scutite) → **0% FP**.

**Hibridul are acum 4 componente → 5 tactici MITRE acoperite. Rezultat (episod):**

| Categorie | clasif | F | recon | destruct | FULL |
|---|:--:|:--:|:--:|:--:|:--:|
| IN-DIST escaladare | 100% | 67% | 0% | 0% | **100%** |
| HELD dens (Peirates) | 100% | 100% | 0% | 0% | **100%** |
| HELD rar (Stratus) | 0% | 67% | 33% | 0% | **67%** |
| HELD diluat (lowslow) | 100% | 100% | 0% | 0% | **100%** |
| **HELD LATERAL (impersonare)** | 100% | 100% | 0% | 0% | **100%** |
| **HELD IMPACT** | 0% | 0% | 0% | 100% | **100%** |
| **HELD DEFENSE EVASION** | 0% | 100% | 0% | 100% | **100%** |
| IN-DIST recon-sa | 0% | 0% | 100% | 0% | **100%** |
| HELD recon (rakkess) | 0% | 0% | 100% | 0% | **100%** |
| BENIGN can-i | 0% | 0% | 0% | 0% | **0%** |
| BENIGN normal | 0% | 4% | 0% | 0% | **4%** |

### Matrice de acoperire MITRE ATT&CK for Containers (DOAR plan de audit API)

| Tactică | Acoperire | Tehnici / scenarii |
|---|:--:|---|
| Discovery | ~85% ✅ | T1613 (resurse), T1069 (can-i: recon-sa, rakkess) |
| Credential Access | ~70% ✅ | T1552.007 (secrete), T1528 (token SA: Stratus, Peirates) |
| Privilege Escalation | ~75% ✅ | RBAC/cluster-admin binding (synthetic, Peirates, lowslow) |
| Execution | ~70% ✅ | T1609 (exec), T1610 (deploy) |
| **Lateral Movement** | ~40% ✅ nou | **T1134 impersonare** — 2 episoade: (ses.17) impersonare+secrete, (ses.18) impersonare PURĂ |
| **Impact** | ~40% ✅ nou | **T1485** ștergere masivă + **T1496** workload-hijack (adversary-impact) |
| **Defense Evasion** | ~30% ✅ nou | **T1070** delete events/webhook/networkpolicy/CRB (adversary-evasion) |
| Persistence | ~15% ⚠️ | parțial (CRB durabil); backdoor SA/webhook = lucru viitor |
| Initial Access | ~25% — | mostly non-API-observabil (modelat ca rezultat: token furat) |

**Onestitate (limite v1.4 — confirmate prin verificare adversarială):**
- **N mic per scenariu nou** (impact 1 episod ses.15, evasion 1 ses.16, **lateral 2** ses.17+18) → „100%" =
  1/1 sau 2/2, intervale de încredere largi. A se raporta explicit ca demonstrativ; recomandat ≥3-5 episoade/scenariu.
- **Trăsătura `has_impersonation` e CORECTĂ, SPECIFICĂ (1.0 pe toate 38 ferestre lateral, 0 peste tot altundeva,
  0 FP) și DEMONSTRAT NECESARĂ pentru overlay-ul F.** *Nu* e cauzală pentru **clasificator** (importanță XGBoost=0.0,
  recall identic cu/fără ea — fiindcă TRAIN are 0 pozitive cu impersonare → arborele nu poate face split). Valoarea
  ei e în **F**: am colectat 2 episoade lateral — (ses.17) impersonare + secrete cross-ns, (ses.18) **impersonare
  PURĂ** (fără secrete/ștergeri, singurul semnal = `has_impersonation`). **Ablație: pe episodul pur, F FĂRĂ termenul
  de impersonare îl RATEAZĂ (NU), F CU el îl prinde (DA)** → trăsătura e necesară pentru detecția impersonării-only.
  (Clasificatorul prinde și episodul pur, dar via breadth-ul de enumerare — drum secundar, nu via impersonare.)
- **Impact/Evasion sunt prinse de REGULA `destruct`, NU de ML** (severity=0 pe toate). Evasion „prins de F 100%" e
  **incidental** (1/119 ferestre, doar via `has_crb` din CRB-ul propriu creat în scenariu).
- **`exec` cross-ns declarat la lateral NU apare în ferestre** (`has_exec=0` pe toate 18) — a NU se afirma că lateral
  include exec; ce se vede e impersonare + citiri secrete în 2 ns.
- **Risc structural allowlist (recon + destruct):** `allowed(user)` face match pe **SUBSTRING** și short-circuit
  necondiționat → o identitate allowlistată compromisă SAU un atacator cu nume conținând un substring ALLOW scapă
  100%. Neexploatat în set (0 coliziuni), dar de raportat; mitigare viitoare: match exact/prefix + anomalie de rată.
- **Persistence** rămâne golul principal neacoperit.

---

## CHANGELOG v1.3 (redesign ONEST, post-verificare adversarială — supersedează v1.2)

O verificare adversarială (mai mulți auditori independenți care au reprodus cifrele) a expus că rezultatele v1.2
erau **umflate** de construcția testului. v1.3 le remediază și **sacrifică cifrele optimiste pentru cifre held-out
mai mici dar REALE** (conform Arp et al. *"Dos and Don'ts of ML in Security"* + Pendlebury *TESSERACT*):

- **Problema 1 — redundanță sintetică (leakage intra-distribuție):** 88% (138/157) din ferestrele de escaladare
  din testul sintetic erau **byte-identice** cu pozitive din train (generatorul producea doar 176 vectori distincți
  din 362 ferestre). v1.3: **dedup pe vector** + sinteticul retrogradat la „validare in-distribution", generalizarea
  mutată exclusiv pe **held-out**.
- **Problema 2 — test ne-attacker-disjunct:** sinteticul de test folosea aceiași atacatori ca train-ul. v1.3 mută
  **Stratus din train în held-out** și adaugă o **identitate atacator NOUĂ** (`adversary-stealth`) → escaladarea de
  generalizare = **Stratus (rar) + Peirates (dens) + lowslow (diluat)**, toate attacker+tool-disjuncte.
- **Problema 3 — `n_list` = cârjă de densitate:** modelul învăța „escaladare ⟺ listează mult" (`n_list` median 14 la
  atacurile sintetice, trăsătura #1, importanță 0.31). Pe atac diluat (`n_list=0`) → **ratat total**. v1.3 **scoate
  `n_list`** → set **A_minus_nlist (28 trăsături)**; modelul se sprijină acum pe `has_secret` (importanță 0.57,
  invariantă la densitate). Confirmat că A_minus_nlist domină alternativele (invariant-only urcă FPR la 8–20%).
- **Problema 4 — testul lipsă pentru F:** v1.2 nu conținea regimul de **densitate mică** pentru care a fost creat F.
  v1.3 adaugă **atac DILUAT held-out** (`adversary-stealth`, sesiune 14, 119 ferestre): densitate mică (`n_secrets`
  0.34, `n_list` 0) dar **primitivă periculoasă prezentă** (`has_crb` 45%, `severity` median 2).
- **`rakkess "86%"` reconciliat ca artefact:** apărea DOAR la conjuncția (`n_list` în trăsături ȘI Stratus în train);
  cade la **0%** la orice schimbare (rakkess are `n_list=0`; detectează permisiuni prin `create` de
  SelfSubjectAccessReview, `n_create`=17.7). Eliminat de redesign → modelul **NU** detectează recon; reconul rămâne
  exclusiv treaba detectorului allowlist+rată.

**Rezultate v1.3 (pipeline hibrid onest, pe EPISOD; clasif A_minus_nlist + overlay F + recon allow/rată):**

| Categorie | clasificator | overlay F | clasif+F | recon allow+rată |
|---|:--:|:--:|:--:|:--:|
| IN-DIST escaladare (sintetic) | 100% (3) | 67% | **100%** | 0% |
| HELD escaladare **DENSĂ** (Peirates) | 100% (1) | 100% | **100%** | 0% |
| HELD escaladare **RARĂ** (Stratus) | 0% (3) | 67% | **67%** | 33% |
| HELD escaladare **DILUATĂ** (lowslow) | 100% (1) | 100% | **100%** | 0% |
| IN-DIST recon-sa | 0% | 0% | 0% | **100%** |
| HELD recon (rakkess) | 0% (3) | 0% | 0% | **100%** |
| BENIGN can-i | 0% (4) | 0% | 0% | **0%** |
| BENIGN normal | 0% (57) | 4% | 4% | 0% |

**F CUANTIFICAT** (window-level, unde modelul cedează): **+52pp** pe Stratus rar (0→52%), **+55pp** pe diluat
(A_minus_nlist 36→91%), cost FP doar **+1.1pp** pe benign → câștig net **+51/+54pp**. F = **plasă de siguranță pentru
densitate mică**, demonstrată acum cu atac held-out real (înainte era nedemonstrată).

**Onestitate (limite):** N held-out mic (Stratus 21 ferestre/3 episoade, Peirates 23/1, lowslow 119/**1 episod, 1
identitate**) → cifre punctuale, intervale largi. Cifra diluat model-singur „36%" e specifică configului determinist
(cu subsampling: 44–64%). 1 episod Stratus (sesiunea 8) nu are nicio primitivă periculoasă → imposibil de prins
(absență de semnal). Posibilă **circularitate în F**: predicatul F și `severity` derivă din aceleași primitive ca
datele. FPR măsurat doar pe benign sintetic.

---

## CHANGELOG v1.2 (istoric — vezi v1.3 mai sus pentru starea curentă)

v1.1 a închis golul de **recon** dar a expus două probleme oneste pe care v1.2 le remediază:
(i) modelul învăța **densitatea** atacurilor scriptate (overfitting pe tempo), nu tehnica; (ii) cifrele de recon
erau **in-sample** (recon-sa în train) și recon-ul de permisiuni e **genuin ambiguu** cu automatizarea benignă.

**Ce s-a schimbat în v1.2:**

- **(A) Trăsături invariante la densitate — 29 trăsături** (15 vechi + **14 noi**). Noile trăsături nu mai depind de
  câte evenimente/secundă produce atacatorul, ci de *ce face*: **flaguri de prezență** (`has_secret`, `has_exec`,
  `has_rbac_write`, `has_crb`, `has_forbid`), **rate normalizate pe fereastră** (`secret_rate`, `rbac_rate`,
  `create_rate`), **lățime** (`secret_ns` = în câte namespace-uri se citesc secrete), **scor de severitate**
  (`severity` = combinație ponderată de primitive rare) și **cumulativ pe actor** (`cum_secrets`, `cum_rbac_w`,
  `cum_exec`, `cum_crb`). Scop: un atacator „low-and-slow" care diluează tempo-ul rămâne detectabil.
- **(D) Antrenare pe tempo variat + unelte reale tool-disjuncte.** Colectarea sintetică folosește tempo variat;
  în plus, **unelte terțe** intră în pipeline: **Stratus Red Team** (DataDog) în TRAIN (escaladare), **Peirates**
  (InGuardians) **HELD-OUT** (escaladare), **rakkess** (`kubectl access-matrix`) **HELD-OUT** (recon). Split
  **tool-disjunct** (analog disjuncției spațiale TESSERACT, Pendlebury et al.): modelul e testat pe o unealtă de
  atac pe care **nu a văzut-o niciodată**.
- **(F) Overlay de severitate** (la nivel de episod, peste clasificator): alarmă dacă apar **primitive rare** —
  creare `clusterrolebinding`/`clusterrole`, `exec` în pod, sau dump de secrete în **≥2 namespace-uri**. Combate
  direct overfitting-ul pe densitate (regulă deterministă, independentă de tempo).
- **(Recon = allowlist + rată, NU clasificator).** Reconul de permisiuni e scos din clasificator (unde producea
  FPR ireductibil) și tratat prin **listă-albă de identități de automatizare** cunoscute (CI/scanere/operatori/SA
  control-plane) + **prag de rată `can-i`**: o identitate **ne-allowlistată** care face `can-i` în volum = recon.

**Rezultate (pipeline hibrid v1.2, evaluare pe EPISOD, split tool-disjunct):**

| Categorie | clasificator | overlay F | clasif+F | recon allow+rată |
|---|:--:|:--:|:--:|:--:|
| ESCALADARE (test sintetic, sesiune-disjoint) | 100% (3) | 67% | **100%** | 0% (corect) |
| **ESCALADARE held-out (Peirates, tool-disjoint)** | **100%** (1) | **100%** | **100%** | 0% (corect) |
| RECON sintetic (recon-sa) | 0% (corect, exclus) | 0% | 0% | **100%** (1) |
| RECON extern held-out (rakkess, tool-disjoint) | 100% (3) | 0% | 100% | **100%** (3) |
| BENIGN can-i (ci-deployer/compliance) | 0% | 0% | 0% | **0%** (4) |
| BENIGN normal | 0% (78) | 4% | 4% | 0% |

- **Generalizare tool-disjunctă (anti-circularitate):** clasificatorul antrenat pe **sintetic + Stratus** detectează
  **Peirates** (unealtă terță nevăzută) la **100%** (atât clasificator, cât și overlay F). La nivel de fereastră:
  **23/23** ferestre Peirates au `has_secret`, **22/23** ating `severity≥2`, secrete citite în **5 namespace-uri**.
- **Recon rezolvat onest:** v1.1 dădea rakkess **0.8%** prin clasificator (cu FPR ireductibil); v1.2, prin
  allowlist+rată, prinde **recon-sa 100% + rakkess 100%** cu **0% fals-pozitiv pe `can-i` benign**.
- **Importanța trăsăturilor** (clasificator): `n_list` 0.37, `has_secret` 0.21, `n_distinct_resource` 0.11 —
  noua trăsătură de prezență `has_secret` urcă în top, confirmând că semnalul e *acțiunea*, nu densitatea.

**Caveat-uri oneste (N mic — set de REFERINȚĂ, nu scară masivă):** held-out Peirates = **1 episod / 23 ferestre**;
escaladare test sintetic = 3 episoade; recon-sa = 1 episod. Stratus a produs puține ferestre de train (**21**) →
escaladarea în train se sprijină majoritar pe sintetic. Overlay-ul F are un mic FPR pe benign-normal (**4%**).
**Limită a reconului:** allowlist+rată prinde identități *necunoscute*; o identitate *allowlistată compromisă*
care face recon ar **scăpa** (mitigare viitoare: baseline per-identitate, nu doar allowlist binară).

---

## 1. Motivație (Motivation)

**De ce a fost creat?** Nu există un set de date public, citabil, pentru IDS pe **audit-ul API-server Kubernetes**
(planul de control/operațional). Seturile clasice (CICIDS2017, UNSW-NB15, CTU-13 = rețea; ADFA-LD = syscall) nu
acoperă atacurile la nivel de API K8s (abuz RBAC, token SA furat, escaladare de privilegii, recon de permisiuni).
v1.2 adaugă în plus o **validare tool-disjunctă cu unelte red-team terțe** (Stratus, Peirates, rakkess) pentru a
testa generalizarea dincolo de scripturile proprii — adresând critica de **circularitate** (atac generat și
detectat de același autor). Scope STRICT: **doar planul operațional / API-server** (rețeaua și syscall-urile sunt
acoperite de componentele separate Flow și Falco din sistemul IDS).

**Cine l-a creat?** Lucrare de disertație (master), autor griandreea4@gmail.com, 2026.

**Finanțare:** subscripție personală „Azure for Students" (cost real ≈ $0 Log Analytics — sub cota gratuită de 5GB).

---

## 2. Compoziție (Composition)

**Ce reprezintă o instanță?** O **fereastră glisantă de 20 de evenimente de audit consecutive ale unui actor**,
reprezentată prin **29 trăsături comportamentale (set A)** + etichetă + identitatea actorului + **unealta sursă**
(`tool` ∈ {synthetic, stratus, rakkess, peirates}) + sesiune. Featurizarea pe ferestre captează comportamentul de
sesiune; trăsăturile sunt **comportamentale, nu username brut** → evită leakage-ul circular.

**Sursa brută:** colectare reală pe un cluster AKS managed (`kube-audit` + `kube-audit-admin`, nivel **Metadata**),
exportată din Azure Log Analytics. **13 sesiuni** de colectare (`sessions.txt`), **38 914 evenimente brute** →
**22 422 ferestre**.

**Partiții (instanțe = ferestre), split TOOL-DISJUNCT:**

| Partiție | Conținut | Ferestre | Benign | Atac |
|---|---|---:|---:|---:|
| `train` | sintetic ses. 1–4 + **Stratus** (escaladare) + fundal benign al sesiunilor de unealtă | 9 915 | 9 353 | 562 |
| `test` | sintetic ses. 5,6,13 (sesiune-disjoint) | 2 787 | 2 575 | 212 |
| `recon_eval` | **rakkess** held-out (recon `can-i`, tool-disjunct) | 9 697 | 0 | 9 697 |
| `peirates_eval` | **Peirates** held-out (escaladare, tool-disjunct) | 23 | 0 | 23 |
| **Total** | | **22 422** | 11 928 | 10 494 |

**Pe unealtă:** synthetic 12 681 · rakkess 9 697 · Peirates 23 · Stratus 21. (rakkess domină numeric fiindcă
`access-matrix` emite câte un `selfsubjectaccessreview` per resursă×verb → multe ferestre de recon.)

**Cele 29 trăsături (set A):**
- **15 vechi:** `forbid_ratio, n_forbid, n_events, n_distinct_resource, n_distinct_verb, n_distinct_ns, n_secrets,
  n_exec, n_rbac, n_create, n_delete, n_list, n_4xx, n_selfreview, selfreview_ratio`.
- **14 noi (invariante la densitate):** `has_secret, has_exec, has_rbac_write, has_crb, has_forbid` (prezență);
  `secret_rate, rbac_rate, create_rate` (rate normalizate); `secret_ns` (lățime namespace secrete);
  `severity` (= 3·has_crb + 2·has_exec + 2·(secret_ns≥2) + has_rbac_write); `cum_secrets, cum_rbac_w, cum_exec,
  cum_crb` (cumulativ pe actor, contra low-and-slow).
- `user`, `tool`, `session` = metadate (audit/episod/split), **EXCLUSE** din input-ul modelului.

**Etichete (ground-truth):** controlăm cine e adversar → etichetare prin identitate + unealtă.
`ATAC = identitățile adverse sintetice {victim-sa, adversary-external, adversary-insider, recon-sa}` ∪
`{Stratus, Peirates, rakkess}`. Ground-truth **exactă prin construcție** (noi am rulat scripturile/uneltele).

**Lipsesc date?** Nivel audit = **Metadata** → fără corpul cererii. Avem: identitate, grupuri, `sourceIPs`,
`userAgent`, `verb`, `objectRef`, `responseStatus.code`, `authorization.k8s.io/decision`.

**Confidențialitate:** testbed propriu, telemetrie de audit **reală**, fără PII.

---

## 3. Proces de colectare (Collection Process)

**Cluster:** AKS real (`intrusion-detection-aks`), diagnostic `kube-audit` → Log Analytics; interogare prin
`az rest` la `api.loganalytics.io` (`az monitor` stricat local).

**Benign realist** — operatori reali (cert-manager, ArgoCD lean, kube-prometheus-stack), controllere native,
**6 actori-umani** pe roluri (certificate client semnate de CA-ul clusterului) + SA de automatizare (ci-deployer,
compliance-scanner-sa).

**Atac realist — două straturi:**
1. **Sintetic scriptat** (tempo variat): token SA furat (`victim-sa`→forbid trail), credențial valid abuzat
   (`adversary-external` cluster-admin), insider (`adversary-insider`), recon de permisiuni (`recon-sa`).
2. **Unelte red-team terțe** (tool-disjunct, anti-circularitate):
   - **Stratus Red Team** (DataDog) — TRAIN — `dump-secrets`, `privileged-pod`, `steal-serviceaccount-token`.
   - **Peirates** (InGuardians) — **HELD-OUT** — rulat **în pod** sub SA compromis cluster-admin: dump secrete în
     5 namespace-uri, creare 2× `clusterrolebinding` cluster-admin, enumerare RBAC/SA/pods (`peirates_collect.sh`).
   - **rakkess** (`kubectl access-matrix`, krew) — **HELD-OUT** — recon `can-i` la volum.

**Mapare TTP:** MITRE ATT&CK for Containers — Discovery (T1613), Container Admin Command (T1609), Deploy Container
(T1610), Unsecured Credentials: Container API (T1552.007), Permission Groups Discovery (T1069), escaladare RBAC.

**Interval temporal:** colectat 2026-06-07 (ferestre exacte în `sessions.txt`).

---

## 4. Preprocesare / curățare / etichetare (Preprocessing/Cleaning/Labeling)

- Per actor, evenimente ordonate temporal → **ferestre glisante de 20** → **29 trăsături (set A)** (`export_v2.py`).
- **Anti-leakage:** username brut NU e feature; doar comportament.
- **Dedup** pe `auditID` între sesiuni; fiecare fereastră etichetată cu `tool` pentru split tool-disjunct.
- **Igienă post-atac:** `clusterrolebinding`-urile cluster-admin create de Peirates (`pwn-peirates-*`) + SA/pod
  atacator sunt **șterse** după colectare (datele rămân în CSV).

---

## 5. Utilizări (Uses)

- Antrenare/benchmark de IDS pe audit API K8s cu **pipeline hibrid** (clasificator escaladare + overlay severitate
  + detector recon allowlist/rată).
- **Studiu de generalizare tool-disjunctă** (train pe o unealtă, test pe alta nevăzută) — adresează circularitatea.
- Studiu de robustețe la **densitate/tempo** (trăsături invariante A vs trăsături de densitate).

**Pipeline de referință inclus:** `train_v2.py` (XGBoost A + overlay F + recon allowlist/rată, histerezis K=2).

**GRANIȚA DE DETECȚIE (onest):**
- ✅ **escaladare/acțiuni periculoase** (secrete multi-ns, exec, creare CRB, token furat): detectate, **inclusiv
  tool-disjunct** (Peirates held-out 100%).
- ✅ **recon de permisiuni** de la identitate necunoscută: prins prin allowlist+rată (recon-sa + rakkess 100%).
- ⚠️ **recon de la identitate allowlistată compromisă**: ar scăpa (limită de design — vezi caveat).
- ❌ **TTP off-API** (token local, metadata SSRF, kubelet): invizibile audit-ului API → componenta Falco/runtime.

**Ce să NU faci:** nu trata held-out Peirates (N=1 episod) ca dovadă statistică tare — e demonstrație de
generalizare; nu generaliza la TTP off-API; nu folosi pentru rețea/syscall.

---

## 6. Distribuție (Distribution)

- **Licență:** CC BY 4.0. Atribuire necesară.
- **Format:** `ref_v2_all.csv` (29 trăsături + `user,tool,session`) + `sessions.txt` + scripturi de reproducere.

---

## 7. Întreținere (Maintenance)

- **Contact:** griandreea4@gmail.com. **Versionare:** v1.2 (2026-06-07). **Predecesor:** v1.1 (vezi
  `reference_dataset/DATASHEET.md`). **Reproductibilitate:** `export_v2.py`, `train_v2.py`, `tool_collect_v2.sh`,
  `peirates_collect.sh`, `setup_actors.sh`, `scale_collect.sh`.

---

## Limitări cunoscute (rezumat onest)
1. **N mic pe held-out** (Peirates 1 episod / 23 ferestre; escaladare test 3 episoade; recon-sa 1) → demonstrație
   de generalizare, nu CI strâns. Set de **referință**, nu scară masivă.
2. **Stratus** a produs doar 21 ferestre de train → escaladarea în train e majoritar sintetică.
3. **Nivel Metadata** → fără corpul cererii (unele atacuri RBAC se disting doar prin obiectul-țintă).
4. **Recon** detectat prin **allowlist+rată**, nu prin clasificator → o identitate allowlistată compromisă scapă.
5. Overlay F are FPR mic (**4%**) pe benign-normal; FPR operațional necesită histerezis (K≥2) — raportat explicit.
6. **TTP off-API** neacoperite (by design — componenta Falco/runtime).
