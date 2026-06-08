# Raport final — Componenta de Audit (API-server) a sistemului IDS Kubernetes

> Document consolidat, gata de teză, cu TOT ce s-a construit și verificat pentru componenta de **detecție pe planul
> de audit / API-server Kubernetes**. Scris onest: separă clar ce e dovedit de ce e demonstrativ.
> Dată: 2026-06-08 · Set: `reference_dataset_v2/ref_v2_all.csv` (**49 424 ferestre, 101 sesiuni, 34 trăsături**) ·
> Pipeline: `train_v2.py` · Cluster: AKS managed real, audit level Metadata.
> **Clasele sintetice regenerate cu variație** (§6.6); **N held-out mărit la prag Wilson ≥70%** (§6.2); **serving
> hardened SRE** (replicas=2/PDB/securityContext/NetworkPolicy); **allowlist ANCORAT**; **split tool-disjunct ZERO
> contaminare** (escaladarea trainează DOAR pe sintetic; toate uneltele externe held-out).
> **v2.1:** **regula `persist`** (CSR/TokenRequest) → persistence 56%→100% tool-disjunct, 0 FP; **finding onest: Stratus
> escaladare 82%/LB52%** (module diverse expun gol pe enumerare-noduri); fix calibrare FP. **v2.1-riguros (post-audit ML):**
> N pe **traiectorii distincte** + recall pe **ferestre nevăzute** (`FULL_nov`) → Wilson strict, doar **lateral+persistence
> ≥70%** (raportarea naivă de 6×72% era umflată de traiectorii identice + leakage la nivel de fereastră — vezi §6.2).
> Disponibilitatea uneltelor externe de validare: `UNELTE_EXTERNE_VALIDARE.md` (deep-research citat).

---

## 1. Ce este și ce NU este

**Scope strict:** detecția intruziunilor pe **planul de audit al API-server-ului Kubernetes** (control-plane).
Rețeaua (DDoS/flow) și syscall/runtime sunt acoperite de componente SEPARATE (Flow, Falco). TTP off-API (token
local, metadata SSRF, kubelet, escape la host) sunt **excluse prin design**.

**Revendicare defensabilă:** *„dataset de REFERINȚĂ + pipeline hibrid reproductibil + studiu de generalizare
tool-disjunct pentru detecția pe planul de audit K8s"*. **NU** „benchmark" (nișa e genuin neacoperită public —
seturile existente sunt flow de rețea sau metrici de pod; niciunul nu conține evenimente de audit API).

---

## 2. Arhitectura de detecție (hibrid defense-in-depth)

Un **clasificator ML** + **6 reguli de suport** deterministe, fiecare acoperind o clasă de atac:

| Componentă | Tip | Ce prinde | Mecanism |
|---|---|---|---|
| **Clasificator** | ML (XGBoost) | escaladare, lateral, impact (ștergere) | trăsături comportamentale `A_minus_nlist` (30), histerezis K=2 |
| **F (severitate)** | regulă | primitive flagrante (CRB/exec/impersonare/secrete multi-ns) | OR pe prezență |
| **recon** | regulă | enumerare permisiuni (`can-i`) | allowlist + rată `n_selfreview≥5` |
| **destruct** | regulă | ștergere masivă (impact/evasion) | allowlist + rată `n_delete≥5` |
| **hijack** | regulă | workload-hijack / cryptominer | allowlist + `n_create_workload≥1` |
| **persist** | regulă | persistence prin client-cert/token | allowlist + `has_csr≥1` SAU `has_tokenreq≥1` (CSR self-approve / TokenRequest abuse) |
| **anom** | regulă | identitate kube-system **necunoscută** (SA fabricat de atacator) | allowlistat-prin-prefix DAR ∉ `known_allow` + rată privilegiată → nu mai e exonerat |

**Alarma finală = clasificator OR F OR recon OR destruct OR hijack OR persist OR anom.**

**Pe identități ALLOWLISTATE (infra de încredere) singurul detector activ e `anom`** (kube-system NECUNOSCUT).
Testarea LIVE (§6.7) a arătat că **atât clasificatorul CÂT ȘI F** produc fals-pozitive pe control-plane-ul managed
(aksService/masterclient creează CRB, cainjector watch secrete multi-ns, falco) → ambele sunt acum **allowlist-gated**.
Pe NE-allowlistate (de unde vin atacurile) toate rămân active: clasificator + cele 6 reguli.

**De ce hibrid (rezultat empiric, nu preferință):** s-a DEMONSTRAT că reconul-`can-i` e fundamental ambiguu cu
automatizarea benignă (ML pe recon → FPR ireductibil), deci reconul stă pe regulă; iar la o **tactică nouă reală
(Persistence via Stratus)** clasificatorul ML dă **0%** — doar regulile o prind. ML singur nu acoperă tot.

---

## 3. Setul de date

**Sursă:** colectare reală pe AKS (`kube-audit` + `kube-audit-admin`, nivel Metadata) → Log Analytics → `az rest`.
O instanță = **fereastră glisantă de 20 evenimente/actor** → 34 trăsături. Etichetare **prin construcție**
(identități/unelte dedicate). Benign realist: infrastructură AKS managed (~73%) + controllere native (~17%) +
operatori reali (cert-manager/ArgoCD/Prometheus) + actori pe certificate + automatizare SA.

**Compoziție (49 424 ferestre, 101 sesiuni):** synthetic 37 372 · rakkess 9 697 · lowslow 826 · impact 448 (variat) ·
lateral 354 · evasion 310 · escv 231 · stratus 85 · persistence 42 (extern) · lateralext 36 (extern) · peirates 23.
*(rakkess = majoritatea ferestrelor de atac, o singură unealtă de recon → raportăm pe EPISOD, nu pe fereastră.)*

**Tactici de atac prezente (MITRE ATT&CK for Containers — doar plan audit):**

| Tactică | Acoperire | Scenarii |
|---|---|---|
| Discovery | ✅ ~85% | T1613 resurse, T1069 can-i (recon-sa, rakkess) |
| Credential Access | ✅ ~70% | T1552.007 secrete, T1528 token SA (Stratus, Peirates) |
| Privilege Escalation | ✅ ~75% | RBAC/cluster-admin binding (synthetic, Peirates, lowslow) |
| Execution | ✅ ~70% | T1609 exec, T1610 deploy |
| Lateral Movement | ✅ nou | T1134 impersonare — 2 episoade (cu secrete + impersonare PURĂ) |
| Impact | ✅ nou | T1485 ștergere masivă + T1496 workload-hijack |
| Defense Evasion | ✅ nou | T1070 delete events/webhook/networkpolicy/CRB |
| **Persistence** | ✅ ~100% (extern) | **Stratus**: create-admin-clusterrole/token/client-cert (regula `persist`) |
| Initial Access | — | mostly non-API (modelat ca rezultat: token furat) |

---

## 4. Trăsăturile (34) și deciziile cheie

**15 vechi** (count/rate de bază) + **19 noi (A)**: prezență (`has_secret/exec/rbac_write/crb/forbid/impersonation`),
rate normalizate, lățime (`secret_ns`), severitate, cumulativ/actor, **impersonare** (`has_impersonation`,
`n_distinct_impersonated`), **workload-create** (`n_create_workload`), **persistence** (`has_csr`, `has_tokenreq`).

**Excluse din clasificator (decizii dovedite prin diagnostic) — folosite DOAR de reguli:**
- **`n_list`** — cârjă de densitate: modelul învăța „atac ⟺ listează mult"; pe atac diluat (`n_list=0`) rata.
  Scoaterea → recall diluat 0%→36%, FPR neschimbat. (`A_minus_nlist`.)
- **`n_create_workload`** — folosit DOAR de regula `hijack`. Inclus în ML producea FP pe crearea benignă de noduri.
- **`has_csr` / `has_tokenreq`** — folosite DOAR de regula `persist` (CSR self-approve / TokenRequest abuse). Ținute
  în afara clasificatorului: sunt semnale binare ne-ambigue de persistence, mai robuste ca regulă ancorată pe allowlist.

**Featurizer cheie — impersonare:** captează AMBELE identități (user real + `impersonatedUser`) și **cheia ferestrei
= atacatorul REAL** (înainte se colapsa pe victimă → impersonarea era invizibilă).

---

## 5. Rezultate finale (pe EPISOD, K=2) — v2.2 RIGUROS (post-audit rundele 5-6)

> **Metodologie strictă** (răspuns la audituri): **N = traiectorii DISTINCTE** (byte-identice colapsate — Wilson cere trials
> independente); **train FEATURE-disjunct** (ferestrele de atac byte-identice cu eval EXCLUSE din train → leakage reparat la
> SURSĂ). **Wilson DUBLU: W(clasif)** = podeaua ML PURĂ; **W(FULL)** = podeaua sistemului HIBRID (clasif OR 6 reguli).

| Categorie | clasif | reguli care prind | **FULL** | **W(clasif)** ML-pur | **W(FULL)** hibrid |
|---|:--:|:--:|:--:|:--:|:--:|
| HELD-id LATERAL (impersonare) | 100% | F 100% | 100% | **70%** (N9) | **70%** (N9) |
| **HELD-EXTERN PERSISTENCE (Stratus)** | 0% | **persist 89%** | 100% | 0% | **70%** (N9) |
| HELD-id DEFENSE EVASION | 90% | destruct 70% | 90% | 60% (N10) | 60% (N10) |
| HELD escaladare DILUATĂ (lowslow) | 100% | F 100% | 100% | 57% (N5) | 57% (N5) |
| HELD-id IMPACT (ștergere) | 89% | destruct 89% | 89% | 56% (N9) | 56% (N9) |
| **HELD kube-system COMPROMIS (allowlistat)** | 33% | **anom 100%** | 100% | 10% (N6) | **61%** (N6) |
| HELD-EXTERN escaladare (Stratus, module diverse) | 0% | hijack 82% | 82% | 0% (N11) | 52% (N11) |
| HELD recon (rakkess) | 0% | recon 100% | 100% | 0% (N4) | 51% (N4) |
| HELD-id ESCALADARE variată (sint) | 56% | F 78% | 78% | 27% (N9) | 45% (N9) |
| HELD-EXTERN LATERAL token (Stratus) | 0% | hijack/persist 100% | 100% | 0% (N3) | 44% (N3) |
| HELD-extern escaladare DENSĂ (Peirates) | 100% | F 100% | 100% | 21% (N1) | 21% (N1) |
| BENIGN can-i | 0% | — | 0% | — | — |
| BENIGN normal | 0% | — | 2% | 0% (N42) | 0% (N42) |

**Două podele raportate ONEST:** **W(clasif)** arată că **ML PUR cade ~0% pe TOATE tacticile externe** (Stratus/persistence/
lateralext/recon) — doar pe escaladare densă (Peirates/lowslow) și lateral generalizează; **W(FULL)** (hibrid) e podeaua reală.
Doar lateral + persistence ating LB ≥70% pe ambele baze relevante. **FP benign 2%** (0% clasif). Importanță: `severity` 0.38.

**FINDING SECURITATE (rundele 5-6) — gaura granitei de încredere DEMONSTRATĂ și ÎNCHISĂ:** o identitate kube-system
**COMPROMISĂ** (SA fabricat, allowlistat-prin-prefix) evadează regulile gated (recon/destruct/hijack/persist exonerează
allowlist-ul) — analiza empirică arată că o regulă de RATĂ pură NU o poate prinde (controllerele benigne fac mass-delete/
token la rate ≥ atac: `n_delete` benign max 14 ≥ atac 12). Semnalul discriminant = identitatea e **NECUNOSCUTĂ**. Regula
**`anom`** (allowlistat-prin-prefix DAR ∉ `known_allow` + rată privilegiată) → **prinde 100%, 0 FP**. *Reziduu onest:* un
controller EXISTENT compromis (token furat, în `known_allow`) ar cere profil comportamental per-identitate (lucru viitor).

**Stratus escaladare 82% (LB 52%):** ML 0%; doar regulile (hijack/F). 3 ratate = enumerare pură de noduri, fără semnal distinct.

---

## 6. ONESTITATEA (verificat adversarial — esențial pentru teză)

Fiecare rezultat a fost reprodus de auditori independenți. Concluziile oneste, **per nivel de dovadă**:

### 6.1 Tăria dovezii e ASIMETRICĂ
- **ESCALADARE = singura cu dovadă TARE, tool-disjunctă** (unelte externe reale Peirates, lowslow). **DAR**
  clasificatorul **eșuează pe Stratus-rar (0/3)** — F + hijack salvează. ML generalizează pe unelte dense, cade pe
  cea rară/sparse.
- **LATERAL/IMPACT/EVASION = dovadă SLABĂ, doar IDENTITY-disjunctă** (același tool/autor/cluster): **lateral ≈ regula
  `has_impersonation`** (scoaterea trăsăturii nu schimbă recall-ul → ML nu bate o regulă trivială); **evasion fragil**
  (cade la diferență comportamentală reală).
  - **IMPACT REGENERAT cu variație genuină** (6 profile distincte: burst/multi-tip/miner în train; interleaved/churn/
    nuke held-out) — repară redundanța de șablon (byte-identic held-out↔train **40%→14%**). Numărul ONEST devine
    **clasif 67%** (era umflat la 100% de clona `imp-3`): modelul ratează ~1/3 din comportamentele de impact cu
    adevărat noi; `destruct` acoperă diferența → FULL 100%. **Acesta e modelul corect de raportare: regenerează cu
    variație, nu șterge cazul incomod.**
- **PERSISTENCE și LATERAL-token (ambele EXTERNE, Stratus) = prinse 100% de REGULI, ZERO ML** (clasificator 0% la
  ambele). Persistence: F via `has_crb` (create-admin-clusterrole) + recon via `can-i`. Lateral-token: F via
  `has_exec` (steal-token execă) + hijack via creare pod + recon. **Clasificatorul NU înțelege tactici/unelte genuin
  externe** — un pattern CONSISTENT pe 2 teste tool-disjuncte independente, care validează empiric defense-in-depth
  și bornează generalizarea ML. *Caveat: regulile prind prin EFECTE SECUNDARE (exec/workload/can-i ale modulelor
  Stratus), nu „înțelegând" tactica; un token-reuse pur (doar create-token) ar putea scăpa.*

### 6.2 N held-out + Wilson LB — RIGUROS (corectat după auditul ML runda 5)
S-au colectat **+45 episoade** (total 101 sesiuni). Raportarea inițială („6 categorii la 72%") s-a dovedit **optimistă**:
un audit ML a expus DOUĂ probleme metodologice, ambele REPARATE:
1. **N umflat de traiectorii byte-identice** — Stratus refolosea același modul pe sesiuni diferite → traiectorii
   identice; lowslow/lateralext aveau profile prea similare. **Fix:** colapsez traiectoriile byte-identice înainte de a
   număra N (`catsig` în `train_v2.py`). N distinct: lowslow **10→5**, lateralext **6→3**, Stratus **15→11**, escv/impact/
   lateral 10→9. Wilson presupune trials INDEPENDENTE — acum e respectat.
2. **Leakage la nivel de fereastră** — dedup-ul era doar în train, deci 10-19% din ferestrele de eval sintetice erau
   byte-identice cu train (features identity-agnostice + comportamente similare). **Fix:** metrica `FULL_nov` =
   detecție pe ferestre GENUIN nevăzute (`ep_class_novel` exclude ferestrele din `TRAINPOS`). Wilson calculat pe `FULL_nov`.

**Wilson95 LB RIGUROS (pe `FULL_nov`, N distinct): doar 2 categorii ≥70%** — **lateral 70%** (N=9, identity-disjunct) și
**persistence 70%** (N=9, tool-disjunct extern, regula `persist`). Restul: evasion 60%, lowslow 57%, impact 56%, Stratus
52%, recon 51%, escv 45%, lateralext 44%, Peirates 21% (N=1). **FP benign 2%** (pe traiectorii distincte). *De ce contează
Wilson:* la N mic „100%" e fragil; LB e podeaua onestă la 95% încredere. **Lecția rundei 5:** numărarea naivă a
episoadelor (perechi sesiune×identitate) supraestimează când traiectoriile se repetă sau ferestrele se scurg train↔eval —
raportarea corectă cere dedup de traiectorie + evaluare feature-disjunctă. Pentru LB≥70% riguros pe toate clasele ar
trebui ~12-15 episoade GENUIN distincte/clasă (comportamente diverse, nu reluări).

**Important — diversitatea de module a EXPUS două adevăruri (onestitate, nu regresie):**
- **Persistence era prins doar 56%** (înainte N=1 dădea iluzoriu 100%): `create-client-certificate` (CSR) și
  `create-token` (TokenRequest) evadau toate regulile. **Reparat cu regula `persist`** (2 trăsături noi `has_csr`/
  `has_tokenreq`, ancorată pe allowlist) → **persistence 100%, LB 70%, ZERO cost FP** (tot benign-ul cu CSR/token e
  control-plane allowlistat: kubelet/aksService/certificate-controller).
- **Stratus escaladare e 82% (LB 52%), nu 100%** — vezi excepția onestă din §5. Cele 3 ratate (enumerare pură de
  noduri) nu lasă semnal distinct de benign; nu le închidem ieftin fără risc de FP pe enumerarea benignă → raportat ca limită.

### 6.3 Costul de FP — onest și diagnosticat
- Pipeline-ul ML-centric a urcat FPR la 9%; **diagnosticul (v1.3 + câte o clasă) a găsit sursa: clasa Impact, și NU
  ștergerea ci semnalul de CREARE al minerului** (prindea crearea benignă de noduri). **Fix:** Impact antrenat doar
  pe ferestre de ștergere → **FPR 9%→4%**, detecția neschimbată.
- A fost găsit și reparat un **bug de allowlist** (cheia pe uid scurt nu prindea prefixele `system:serviceaccount:`)
  → benign-normal FP 11%→4%, fără regresii (0/22 atacatori exonerați greșit).

### 6.4 Riscuri de design (reguli) — cu remedii aplicate
- **[REPARAT] Allowlist ANCORAT (exact + prefix de namespace), NU substring:** `allowed(u)` = `u in ALLOW_EXACT or
  u.startswith(ALLOW_PREFIX)`. Elimină bypass-ul: un atacator în `default` (system:serviceaccount:default:adversary-*)
  sau cu nume conținând un token allowlistat (ex. `sre-oncall-evil`) NU mai e exonerat. Verificat: 0 atacatori
  exonerați, acoperire benign identică (0 regresie), FP neschimbat 5%. Reziduu acceptabil: un SA *în* kube-system
  rămâne de încredere (graniță de încredere reală — compromiterea kube-system = compromitere totală).
- **`hijack` fragil în producție:** garanția 0 FP e doar pe acest set; orice creator de workload ne-allowlistat
  (Helm, operatori custom, ArgoCD, jobs CI, HPA) ar da FP la pragul 1. ALLOW e listă mică, cluster-specifică
  (mitigare viitoare: prag adaptiv + baseline per-identitate).
- **[REMEDIAT parțial] Persistence:** în v2.0 un modul fără `create-clusterrole` evada totul (CSR/token → 0%). v2.1
  adaugă regula `persist` (CSR self-approve + TokenRequest) → cele 3 module Stratus de persistence sunt acum prinse
  100%. Reziduu: o cale de persistence care NU atinge CRB/CSR/token (ex. webhook durabil mutant) ar putea încă scăpa.
- **`anom` (kube-system compromis) — limite ONESTE (audit runda 7):** regula prinde SA-uri FABRICATE necunoscute, dar are
  3 reziduuri reale: **(a) „0 FP" e tautologic** — `KNOWN_ALLOW` = TOT benign-ul observat, deci 0 FP prin construcție; la
  deploy, un controller/operator LEGITIM NOU (Helm/operator custom/upgrade AKS/ArgoCD app) ar declanșa `anom` până e adăugat
  în baseline (aceeași fragilitate ca `hijack`); **(b) evaziune prin name-collision** — un atacator care își numește SA-ul
  fabricat ca un controller existent (`deployment-controller`) cade în `KNOWN_ALLOW` și ocolește `anom` (regula e o listă de
  NUME, nu un profil comportamental); **(c) controller EXISTENT compromis** (token furat, ∈ KNOWN_ALLOW) nu e prins. Remediu
  pentru toate trei = baseline COMPORTAMENTAL per-identitate (nu listă de nume) — lucru viitor.
- **[lărgit în v2.4, după testarea live]** Pe o identitate ALLOWLISTATĂ, **toate** detectoarele sunt gated **cu excepția
  `anom`** (clasif + F + recon/destruct/hijack/persist) — fiindcă pe control-plane-ul managed reduc FP la zero (validat live).
  Consecință onestă: o **identitate allowlistată CUNOSCUTĂ compromisă** (token de controller furat) evadează tot, mai puțin
  `anom` (care nu se aplică identităților din `known_allow`). Reziduu real → cere baseline COMPORTAMENTAL per-identitate (lucru viitor).
  `anom` prinde doar identitățile allowlistate-prin-prefix NECUNOSCUTE (SA fabricat în kube-system).

### 6.5 Limite generale
- **Nivel Metadata** (fără corpul cererii); **un singur cluster, un autor, o zi** → fără disjuncție temporală/cross-cluster.
- **FPR măsurat doar pe benign sintetic** (același autor) → producția reală, mai zgomotoasă, ar putea crește FP.
- **Persistence**: cele 3 module Stratus (CRB/CSR/token) sunt acum acoperite 100% (regula `persist`); căi off-pattern
  (webhook durabil mutant, backdoor fără CRB/CSR/token) rămân neacoperite.
- **Stratus escaladare 82% (LB 52%)**: enumerarea pură de noduri (node-proxy/`list nodes`) evadează — fără semnal distinct de benign.

### 6.6 Diversitatea claselor sintetice (audit anti-redundanță)
Un audit (vectori distincți/total + suprapunere byte-identică held-out↔train) a verificat că sinteticul NU produce
intrări identice inutile pentru generalizare. Clasele template inițial (escaladare in-dist 88% byte-identic;
impact 40%; evasion 23% diversitate) au fost **regenerate cu variație comportamentală** (profile distincte pe
trăsăturile modelului, split pe identitate, held-out comportamental diferit):

| Clasă | diversitate | held-out byte-identic train | detecție clasif (held-out variat) |
|---|:--:|:--:|:--:|
| ESCALADARE | 88% | 3% | **67%** (vs 100% pe testul templat) |
| LATERAL | 94% | 6% | 100% |
| IMPACT | 67% | 14% | 100% |
| EVASION | 75% | 3% | 100% |

**Efect:** numerele de detecție reflectă acum **generalizare reală, nu clone**. Cel mai important — escaladarea
variată dă **67%** la clasificator (testul templat dădea 100% iluzoriu), revelând limita reală. **Lecție metodologică:
redundanța de șablon se repară prin VARIAȚIE de comportament, nu prin ștergerea cazului incomod** (Arp et al.: evită
metrici umflate de redundanță). Efect secundar pozitiv: diversitatea de train a urcat detecția Persistence 0%→100%
(clasificatorul a învățat primitiva CRB-create din profilul rbac-create), la un cost de +1pp FP benign (FULL 5%).

### 6.7 Testare LIVE pe AKS managed — finding de FP (predicția shadow-FP confirmată) + remediu
Sistemul a fost rulat **LIVE end-to-end** pe AKS managed: adapter Log Analytics (`audit_loganalytics_adapter.py`,
managed identity) → poll kube-audit → ferestre per actor → POST `/predict/raw` → alertă. **Finding imediat (exact ce
prezisese auditul ML — testul „shadow-mode FP"):** clasificatorul de PRODUCȚIE produce **fals-pozitive pe benign-ul de
control-plane** pe care testul offline (îngust, sesiunile 5-6) nu-l acoperea — `aksService` (update leases),
`generic-garbage-collector`, `resourcequota-controller`, `system:apiserver` etc., toate cu prob ≈0.675 pe ferestre
degenerate (un verb/o resursă, severity 0). **NU bug de trăsături** (verificat: features corecte) — FP genuin de model
pe distribuția largă de infra, nemăsurat offline. Diversificarea testului live a expus **3 surse de FP**: (1) clasif pe
control-plane (aksService leases); (2) **`F` pe `masterclient`** (creează/șterge `clusterrolebindings` legitim, reconciliere)
și **`cainjector`** (watch secrete multi-ns); (3) clasif pe **`falco-metacollector`** (NE-allowlistat, deși e componentă a IDS-ului).
**Remediu (v2.3→v2.4):** clasificatorul ȘI `F` devin **allowlist-gated** (pe infra de încredere doar `anom` rămâne activ);
`falco` adăugat în allowlist (componentă de încredere). **Verificat LIVE end-to-end (v2.4):** adapter polează 559 ev/31 actori
→ **ZERO fals-pozitive** (masterclient/cainjector/falco/aksService toate `reasons=[]`); atacul `compromised-ctrl` prins prin
Log Analytics → `anom`; `adversary` ne-allowlistat → `clasificator+F`. **Lecții oneste:** (a) pe un cluster managed real,
overlay-ul de severitate `F` NU poate fi ungated (control-plane-ul face CRB/secret-multi-ns benign) → gating-ul lui
**lărgește reziduul granitei de încredere** (controller cunoscut compromis evadează și `F`); (b) FP pe benign NE-allowlistat
NOU (app SA legitim) rămâne posibil → confirmă că **testul #1 e shadow-FP burn-in pe benign real multi-cluster**.

---

## 7. Formularea ONESTĂ pentru lucrare (recomandare)

> Sistemul hibrid (clasificator XGBoost + 4 reguli de suport) detectează în held-out toate cele ~6 tactici de pe
> planul de audit, cu fals-pozitiv 4% (filtrat de histerezis K=2). **Valoarea ML e dovedită tool-disjunct doar pentru
> escaladare** (unelte externe Peirates/lowslow; cu o gaură pe atacul rar Stratus, acoperită de reguli). Pentru
> lateral/impact/evasion, validarea e **identity-disjunctă sintetică** — ML poate învăța aceste clase, dar
> generalizarea pe implementări independente rămâne neverificată (pentru lateral/impact, ML nu depășește o regulă
> transparentă). Pentru tactici complet noi (Persistence, testată cu unealta externă Stratus), **clasificatorul
> cedează (0%) și regulile de suport sunt plasa de siguranță** — ceea ce justifică empiric arhitectura defense-in-depth.

---

## 8. Iterații (rezumat) și reproductibilitate

| Versiune | Ce a adus | Lecție |
|---|---|---|
| v1.2 | clasificator escaladare + F + recon; held-out Peirates tool-disjunct | rakkess „86%" = artefact `n_list` |
| v1.3 | dedup, Stratus held-out, **scos `n_list`**, atac diluat (lowslow), F cuantificat | 88% ferestre test erau clone; metrici umflate |
| v1.4 | închis goluri MITRE: Impact, Evasion, Lateral (impersonare), regula `destruct`, matrice MITRE | impersonare = trăsătură necesară (episod pur) |
| v1.5 | **ML-centric** (lateral/impact/evasion în train), diagnostic FP, fix impact=ștergere | dovadă asimetrică; FP din miner-create |
| v1.6 | regula `hijack` (cazul scos din ML), **Persistence extern (Stratus)**, fix allowlist | ML cedează la tactică nouă → reguli |
| v1.7 | **test lateral EXTERN** (Stratus token-reuse) + cercetare unelte (deep-research) | nu există unealtă pt impact/evasion/lateral-impersonare → scriptarea justificată |
| v1.8 | **Impact regenerat** cu variație (6 profile) — repară clona | byte-identic 40%→14%; recall onest 67% vs 100% iluzoriu |
| v1.9 | **Escaladare+Evasion regenerate** cu variație | toate clasele sintetice variate (div 67-94%); Persistence 0%→100% (efect pozitiv) |
| v2.0 | **allowlist ANCORAT** + **SRE hardening** (replicas=2/PDB/securityContext/NetworkPolicy) + **N held-out mărit** (Wilson LB 51-68%) | bypass eliminat; rigoare + maturitate, nu acoperire |
| v2.0+ | **GitOps drift rezolvat**: imagine IMUABILĂ pushată + manifest canonic unic imuabil+hardenat + anti-affinity, deployat live | imutabilitate ȘI hardening coexistă |
| **v2.1** | **+45 episoade**; **regula `persist`** (CSR+TokenRequest) persistence 56%→100%; **fix calibrare FP** (spw cap 13.27→11) | diversitatea de module EXPUNE adevărul: Stratus escaladare e 80% (nu 100%); golurile se închid cu reguli ancorate, fără cost FP |
| **v2.1-riguros** | **dedup TRAIECTORII** (N onest: lowslow 10→5 etc.) + **`FULL_nov`** (ferestre nevăzute) → Wilson LB strict: doar lateral+persistence ≥70% | raportarea naivă de episoade supraestimează; auditul ML a expus N umflat + leakage la nivel de fereastră |
| **v2.2** | **split train FEATURE-disjunct** + **Wilson dublu** (ML-pur vs hibrid) + **regula `anom`** (kube-system compromis, prins 100%/0 FP) + **digest-pin `@sha256`** live | ML pur cade 0% pe externe (raportat onest); gaura granitei de încredere se închide pt SA fabricat (reziduu: controller existent compromis); imutabilitate reală |
| **v2.3-2.4** | **testare LIVE pe AKS** (adapter Log Analytics→/predict/raw, managed identity); **fix FP**: clasif **ȘI `F`** gated pe allowlist (FP pe control-plane: aksService/masterclient CRB/cainjector secrete/falco) + falco trusted; demo aliniat la v2.2 (kind/Transformer→legacy) | testul live a CONFIRMAT predicția shadow-FP a ML-ului; v2.4 → **ZERO FP live** (559 ev/31 actori), atacuri intacte; F-gating lărgește reziduul granitei de încredere |

### 8.1 Istoric evaluare (dezbatere 3 experți: securitate / ML / DevOps)
Scor mediu pe runde, fiecare după un val de fixuri:

| Rundă | Media | Δ | Ce s-a reparat |
|---|:--:|:--:|---|
| 1 | **6.17** | — | (baseline: allowlist substring exploatabil + IaC ad-hoc) |
| 2 | **7.0** | +0.83 | allowlist ANCORAT + IaC declarativ (server-side apply) |
| 3 | **7.43** | +0.43 | SRE hardening (replicas/PDB/securityContext/NetworkPolicy) + N held-out mărit (Wilson LB 51-68%) + zero contaminare train/test |
| 4 | **7.73** | +0.30 | drift GitOps rezolvat (imagine imuabilă + hardening coexistă, anti-affinity, deployat live) |
| 5 | **7.87** | +0.14 | v2.1: regula `persist` (persistence 56%→100% tool-disjunct, 0 FP), N mărit, fix calibrare FP, deploy live :2.1 |
| 6 | **8.03** | +0.16 | v2.1-riguros: dedup traiectorii (N onest) + `FULL_nov` (ferestre nevăzute) + fix provenance (config version, IMG default) — **a depășit plafonul 8.0** |
| 7 | **8.30** | +0.27 | v2.2: split train FEATURE-disjunct + Wilson DUBLU (ML-pur 0% externe expus onest) + regula `anom` (kube-system compromis 100%/0FP) + **digest-pin `@sha256`** live |

Scoruri rundă 4: securitate 7.65, ML 7.55, DevOps 8.0. Rundă 5: securitate 7.9, ML 7.7, DevOps 8.0 (media 7.87).
**Rundă 6: securitate 8.0, ML 8.1, DevOps 8.0 (media 8.03).** Runda 5 a expus 2 probleme metodologice (N umflat de
traiectorii identice + leakage fereastră) → reparate riguros (§5/§6.2: Wilson strict pe `FULL_nov`/N-distinct; doar
lateral+persistence ≥70%). **ML a spart plafonul 8.0 (7.7→8.1) răsplătind onestitatea metodologică** (acceptarea
cifrelor mai mici dar corecte = disciplină Arp/TESSERACT), NU creșterea recall-ului. Securitate+DevOps rămân la 8.0
(cer capabilitate reală / cosign+CI-CD+digest, nu raportare).
**Rundă 7: securitate 8.2, ML 8.4, DevOps 8.3 (media 8.30).** Toate cele 4 findings ale rundei 6 reparate: split train
FEATURE-disjunct (ablația confirmă leakage-ul umfla escv 8→6/10), Wilson dublu (W(clasif) expune ML-pur 0% pe externe),
regula `anom` (kube-system compromis 100%/0FP), digest-pin `@sha256` live. **Findings rundă 7 (RĂMASE — structurale):**
(securitate) `anom` evitabil prin name-collision + „0 FP" tautologic → cere baseline COMPORTAMENTAL per-identitate; webhook
persistence neacoperită; (DevOps) lipsă cosign + CI/CD + admission verification (digest-pin e convenție, nu impus); (ML)
N mic pe clasele tool-disjuncte (Peirates N=1) — cer mai multă diversitate reală. **Plafonul real spre 9.0 cere
infrastructură (cosign/CI-CD) + capabilitate (baseline comportamental) — dincolo de scopul componentei de audit a tezei.**

**⚠️ Framing ONEST obligatoriu (recomandarea moderatorului) — a NU prezenta 7.73 ca metrică de detecție:**
> Creșterile 6.17→7.73 vin **exclusiv din securitate operațională + maturitate de livrare**, NU din capabilitatea ML.
> Pe axa ML, metricile de **detecție rămân neschimbate** (generalizare tool-disjunctă dovedită DOAR pe escaladare;
> 0% pe tactici externe noi; lateral ≈ regulă trivială; N sub prag, Wilson LB 51-68%). Raportare separată recomandată:
> **„Metrici de detecție ML: ~7.4 (plafon structural). Maturitate deployment/SRE: 8.0. Compozit sistem: 7.73."**

**Plafonul de 8.0 nu se depășește fără câștig REAL de capabilitate:** audit RequestResponse (nu doar Metadata),
validare multi-cluster/temporală, N≥10/categorie (Wilson LB>70%), cosign pe imagine, FP pe benign real, și o contribuție
ML care învață *tactica* (nu efecte secundare) pe ≥2 tactici. Verdict: **teză de master defensabilă și onestă
metodologic** (TESSERACT/Arp: variație nu ștergere, raportare pe episod, Wilson LB), production-capable pe happy-path
pentru escaladare — **NU benchmark / detector multi-tactică validat**.

**Deployment (IaC declarativ, GitOps-clean, FĂRĂ drift) — O SINGURĂ cale canonică:** `k8s/11-audit-xgb.yaml` =
imagine **IMUABILĂ versionată** (`andreeagrigore/runtime-ids-audit:1.9`, cod+model+config copt prin `Dockerfile.audit`,
pushată pe Docker Hub) **ȘI hardenată COMPLET** (replicas=2 + **podAntiAffinity** pe noduri diferite, PDB,
securityContext runAsNonRoot/readOnlyRootFS/drop-ALL-caps/seccomp, **NetworkPolicy strict** ingress doar din
runtime-ids+monitoring). Imutabilitatea și hardeningul **coexistă** (drift rezolvat). Fallback dev fără registry:
`11-audit-xgb-cfgmap-fallback.yaml` (ACELAȘI pod-spec hardenat, ConfigMap via `kubectl apply --server-side`).
`deploy_audit_hybrid.sh` (MODE=image canonic implicit / cfgmap fallback). Model de producție: `models/audit_hybrid_v2/`.
**Deployat live + verificat:** 2 poduri Running pe noduri diferite, image=1.9, healthz=1.9-hybrid.

**Scripturi (în `runtime_ids/deploy/azure/collect/`):**
- *Featurizer + pipeline:* `export_v2.py` (featurizer, 32 trăsături + impersonare + n_create_workload), `train_v2.py`
  (pipeline canonic ML-centric, eval held-out), `train_production.py` (model de producție salvat în `models/audit_hybrid_v2/`).
- *Ablații/diagnostice:* `eval_v2_clean.py` (dedup+regimuri densitate), `eval_model_only.py` (model vs pipeline),
  `eval_ml_coverage.py` (ML pe clasele noi), `eval_fp_diagnostic.py` (v1.3 + câte o clasă → sursa FP).
- *Colectare atac:* `attack_lowslow.sh` (diluat), `attack_gaps.sh` + `attack_gaps_multi.sh` (impact/evasion/lateral),
  `attack_lateral_pure.sh` (impersonare pură), `attack_impact_varied.sh` + `attack_esc_eva_varied.sh` (regenerare cu
  variație), `attack_persistence_stratus.sh` + `attack_lateral_stratus.sh` (tool-disjunct extern Stratus),
  `attack_more_episodes.sh` (+episoade Wilson LB), `peirates_collect.sh`, `tool_collect_v2.sh`.
- *Serving + IaC:* `runtime_ids/service/audit_xgb_service.py`, `deploy/azure/Dockerfile.audit`,
  `deploy/azure/k8s/11-audit-xgb.yaml` (canonic), `deploy/azure/deploy_audit_hybrid.sh`.
- *Cercetare/docs:* `UNELTE_EXTERNE_VALIDARE.md` (deep-research citat), `DATASHEET.md` (Gebru, CHANGELOG v1.2–v2.0).

## 9. Lucru viitor (ce ar întări revendicarea)
1. **Held-out tool-disjunct/autor-disjunct** pentru lateral/impact/evasion (unelte externe reale dacă apar).
2. **Mai multe episoade** per scenariu (≥3-5) + raportare Wilson LB.
3. **Persistence completă** (backdoor SA/webhook durabil) + variante fără CRB (worst-case pt reguli).
4. **Benign independent** (altă zi/cluster) pentru FPR operațional real.
5. **Allowlist robust** (match exact/prefix, nu substring) + anomalie de rată pe identități allowlistate.
