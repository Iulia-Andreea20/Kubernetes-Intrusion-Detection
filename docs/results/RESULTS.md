# Evaluarea componentei Audit pe date reale colectate din AKS

## Metodologie (reproductibilă)
1. **Cluster:** AKS managed (`intrusion-detection-aks`, North Europe, 1× DS2_v2, control-plane Free).
2. **Ingestie audit:** diagnostic settings `kube-audit` + `kube-audit-admin` → Log Analytics workspace `law-ids-aks`.
3. **Activitate etichetată** (doi actori cu certificate distincte):
   - `alice` (rol `view`) → operațiuni normale de citire = **BENIGN**
   - `mallory` (rol `cluster-admin`, cont compromis) → recon → acces secrete → `exec` în pod → escaladare (`clusterrolebinding`) = **ATAC**
4. **Export:** interogare Log Analytics (KQL prin `az rest`), parsare audit → tokeni `verb:resource:subresource`,
   grupare pe actor, ferestre glisante de 20 (identic cu runtime-ul). Etichetă pe actor.
5. **Evaluare:** modelul Audit (Transformer) **neschimbat**, antrenat pe dataset-ul original.

Dataset colectat: **6930** evenimente brute de audit din cloud (actori reali: `aksService`, `system:apiserver`,
`masterclient`, controllere…). Ferestre etichetate: **121 benigne** (alice) + **49 atac** (mallory).

## Rezultate (prag 0.5)

| Actor | Tip | Ferestre | Rezultat | prob medie | prob max |
|---|---|---|---|---|---|
| alice | BENIGN | 121 | **FPR = 18.2%** (22/121) | 0.230 | 0.999 |
| mallory | ATAC | 49 | **detection = 65.3%** (32/49) | 0.678 | 1.000 |

Atacul este **detectat cu certitudine** (cel puțin o fereastră cu prob ≈ 1.0).

### Sweep de prag (compromis operațional)
| prag | FPR benign | detection atac |
|---|---|---|
| 0.50 | 18.2% | 65.3% |
| 0.70 | 18.2% | 65.3% |
| 0.85 | 18.2% | 65.3% |
| 0.95 | 18.2% | 63.3% |

Probabilitățile sunt **saturate** (aproape de 0 sau 1) → mutarea pragului NU schimbă aproape nimic.

Tokeni `<UNK>` (necunoscuți modelului): `create:selfsubjectreviews:`, `list:roles:`.

## Interpretare onestă
- **Modelul TRANSFERĂ pe date reale din cloud:** detectează atacul (65% din ferestrele de atac, sigur semnalat).
- **DAR suferă de domain shift:** FPR de 18.2% pe trafic benign real. Cauza probabilă: monitorizarea benignă
  normală pe AKS înseamnă multe operațiuni `list` pe resurse variate, ceea ce **seamănă cu reconnaissance-ul**
  pe care modelul l-a învățat ca atac. Probabilitățile saturate arată că nu e o incertitudine reglabilă din prag —
  ar fi nevoie de **recalibrare / fine-tuning pe date cloud**.
- **Valoare pentru lucrare:** este exact tipul de constatare riguroasă pe care o aduce evaluarea pe date reale,
  nu sintetice — și motivează ca direcție viitoare adaptarea modelului la distribuția traficului din cloud.

> **Caveat onest:** traficul benign al lui `alice` a fost deliberat foarte „list-heavy" (12 runde × 10 operațiuni
> `get -A` pe toate namespace-urile) — cazul cel mai dificil pentru acest model, fiindcă listările masive seamănă
> cel mai mult cu reconnaissance-ul. Deci 18.2% este mai degrabă o **limită superioară** a FPR; un operator real,
> mai puțin agresiv, ar produce probabil mai puține alarme false. Constatarea calitativă (există domain shift)
> rămâne validă.

---

# Fine-tuning pe date cloud (reducerea domain shift-ului)

## Metodologie
- **Colectare v2** (mai multă/diversă): `alice` (monitorizare) + `dev` (developer: deploy/scale/logs/**exec benign**)
  = benign; `mallory` = 6 episoade de atac. Total 15.343 evenimente brute.
- **Split temporal 70/30 per actor**: `cloud_train` = 362 ferestre (238 benign / 124 atac);
  `cloud_test` = **157 ferestre held-out** (103 benign / 54 atac).
- **Fine-tuning** din greutățile existente, pe *original-train + cloud_train (oversample ×12)*, 30 epoci,
  selecție după (detection − FPR) cu gardă anti-„forgetting" pe testul original.
- Atacurile reproduc tipurile din setul ORIGINAL: `discovery`, `credential_theft`, `token_theft`,
  `container_exec`, `privilege_escalation` (vezi `attack_type` în `data/sequences.jsonl`).

## Rezultate (pe `cloud_test` held-out)
| Metrică | BEFORE (original) | AFTER (fine-tunat) |
|---|---|---|
| FPR benign | 9.7% | **0.0%** |
| Detection atac | 40.7% | **61.1%** |
| orig recall (forgetting) | 95.6% | 96.9% |
| orig f1 | 93.4% | 93.9% |

Model fine-tunat salvat separat în `runtime_ids/models/sequence_audit_cloud/` (originalul rămâne intact).

## Interpretare onestă
- **Fine-tuning-ul a redus FPR la 0% ȘI a crescut detecția** (40.7%→61.1%), **fără catastrophic forgetting**
  (recall pe atacurile originale 95.6%→96.9%). Confirmă diagnoza: problema era distribuția benignă, nu modelul.
- Modelul a învățat că enumerarea masivă + `exec`-ul benign (dev) NU sunt atac, mutându-se pe semnalele
  cu adevărat distinctive (secrete, RBAC, exec ostil după recon).
- **Caveat:** detection 61.1% este la nivel de fereastră — multe ferestre de început de atac sunt recon pur,
  care (corect acum) nu mai declanșează; acțiunile distinctive (secrete/exec/escaladare) sunt prinse, deci
  atacatorul este semnalat în cursul episodului. Dataset cloud mic → pretenții de generalizare modeste.
- Notă: BEFORE aici (9.7% FPR) diferă de baseline-ul rapid de mai sus (18.2%) fiindcă testul held-out v2 e mai
  divers (include benign-ul realist al lui `dev`, nu doar `alice` list-heavy) și e split temporal.
