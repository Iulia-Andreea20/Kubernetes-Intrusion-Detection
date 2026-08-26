# Kubernetes Intrusion Detection

An intrusion detection system for the Kubernetes **control plane**. It reads the API server's audit
log, turns it into sliding windows of activity per identity, and scores each window with a gradient
boosted classifier. It runs live on a managed AKS cluster.

Alongside it sits a second, independent detector on network flows, and an evaluated-but-unusable
third layer on syscalls. The details of all three, and of what does and does not work, are below.

---

## Why the audit plane

A network IDS sees packets. It cannot see an identity binding itself to `cluster-admin`, reading
every secret in the cluster, exec-ing into someone else's pod, or impersonating a service account —
because none of that is distinguishable at the packet level. Those are the attacks that actually
matter in a cluster, and they are all API calls.

The problem is that no public dataset of Kubernetes audit events exists. The datasets people reach
for are network flows (CICIDS, BCCC) or pod-level metrics. So the dataset had to be built, on a real
managed cluster, with real attacker tooling — and building it honestly is most of the work here.

---

## What it detects

| Tactic | Trained on | Validated against |
|---|---|---|
| Privilege escalation | synthetic (`escv`) | Peirates, Stratus Red Team |
| Lateral movement | synthetic impersonation | Stratus token reuse |
| Credential access | synthetic secret dumping | Stratus `dump-secrets` |
| Persistence | synthetic CSR / TokenRequest / CRB | Stratus persistence modules |

Every tactic in scope has a **synthetic half that trains** and an **external-tool half that is held
out**. That pairing is the point: a model that scores well on the tool it never saw has learned the
technique. A model that only scores well on our own scripts has learned our scripts.

**Deliberately out of scope**, and worth saying out loud:

- **Reconnaissance.** At metadata level, an attacker running `kubectl auth can-i` in bulk and a
  benign compliance scanner doing the same thing are the same events. Training on it drove the
  false-positive rate up without a matching gain — AUC 0.33, worse than chance. It is a rule's job,
  not a classifier's.
- **Impact, defense evasion, low-and-slow, compromised-controller.** No public tool implements
  these against the Kubernetes API, so the only thing available to test against is our own scripts.
  Recall measured that way says nothing, so these were removed from the model's scope rather than
  reported optimistically.

Attacks that never touch the API server — a stolen token used off-cluster, metadata SSRF, kubelet
abuse, container escape to the host — are invisible to this by construction, not by oversight.

---

## Results

Two different questions, two different tables.

### Does the model rank attacks above benign traffic?

Window-level, held out, threshold-free:

| Group | ROC-AUC | PR-AUC | recall @ FPR 1% | recall @ FPR 5% |
|---|--:|--:|--:|--:|
| Synthetic (pooled) | 0.977 | 0.954 | 84.7% | 88.2% |
| External tools (pooled) | 0.894 | 0.530 | 29.6% | 52.7% |

Calibration: Brier 0.089, ECE 0.093.

The gap between the two rows is the honest finding. On behaviour it has seen a version of, the model
is strong. On an independent implementation of the same tactic it degrades sharply — and on Stratus
credential access specifically (short, sparse bursts) it nearly fails. Reproduce with:

```bash
python src/model/eval/eval_model_only_standalone.py
```

### Would an operator trust the alerts?

Per attack **run**, using the deployed decision rule (two windows over threshold):

| Operating point | Recall | Precision | False alarms |
|---|--:|--:|--:|
| FPR 1% | 47% | 93% | 3% |
| FPR 5% | 81% | — | 59% |

The 5% row is why the strict threshold is the one that ships. Recall nearly doubles, and the system
becomes unusable: three out of five benign runs raise an alarm. Reproduce with:

```bash
python src/model/eval/test_productie.py 1
```

### On reporting

Accuracy is meaningless here — the set is 74/26 benign, so predicting "benign" scores 74%. PR-AUC and
recall at a fixed FPR are the numbers to read. All benign traffic comes from one cluster over a short
period, so treat AUC as an upper bound; the recall-at-FPR figures are more robust to that.

Where a class has only a handful of distinct episodes, `train_v2.py` reports a Wilson 95% lower
bound rather than a raw percentage. With N=1, "100%" means nothing.

---

## Architecture

```
                    managed AKS
   kube-audit ──► Log Analytics ──► adapter ──┐
                                              ├──► detector ──► Prometheus ──► Alertmanager ──► mail
   audit.log  ──► streamer ───────────────────┘    (XGBoost)         │
   (self-managed)                                                    └──► Grafana
   flow records ─────────────────► flow detector ─────────────────────────┘
                                   (XGBoost + autoencoder)
```

**Audit detector** — FastAPI service holding a 32-feature XGBoost model. `POST /predict/raw` takes an
actor's recent events, builds 20-event sliding windows, scores each, and raises an episode alert when
at least two cross 0.5. Two replicas on separate nodes, pinned by image digest, non-root, read-only
root filesystem, all capabilities dropped, ingress restricted by NetworkPolicy.

**Adapter / streamer** — the same job on two different clusters. A managed control plane gives you no
node to tail, so on AKS the audit stream goes to Log Analytics and the adapter polls it over KQL. On
a self-managed cluster the streamer tails the file directly. The adapter's authentication is the
kubelet managed identity, which means no secret to rotate. Note that Log Analytics ingestion lags by
minutes — detection here is not sub-second, and Event Hub would be the fix.

**Flow detector** — supervised XGBoost fused with an unsupervised autoencoder,
`0.7·Platt(p_xgb) + 0.3·p_ae`, thresholded at FPR 1%. In-distribution the autoencoder adds almost
nothing (AUC 0.972 → 0.973). On a leave-heavy-hitter-out split it earns its keep: 0.64 → 0.86, because
the supervised model has latched onto per-attacker signatures and the autoencoder has not.

**Falco** — integrated, deployed, and it does not work here. On the AKS node kernel (5.15-azure) the
`modern_ebpf` driver is rejected by the verifier, and `kmod` loads via dkms but the engine emits
nothing even when correct rules fire. The assets are kept and runnable on a kernel where capture
works; the claim in the thesis is two functional layers plus one evaluated, not three active ones.

**Correlator** — groups alerts by actor and time window and matches MITRE chains. It runs offline
over stored predictions; it is not wired in as a pod.

---

## The dataset

`src/dataset/reference/ref_v2_all.csv` — 50,978 windows × 38 columns, from 103 collection sessions on
a real AKS cluster with `kube-audit` and `kube-audit-admin` at Metadata level.

One row is a sliding window of 20 audit events for one identity. The 34 features are counts, rates
and presence flags — verb and resource diversity, forbidden-response ratio, secret and RBAC access,
exec, impersonation, plus per-actor cumulative counters so that an attacker who paces themselves
still accumulates signal even though no single window looks alarming.

Labels come from the identity: anything named `adversary-*` or `redteam-*` is an attack, everything
else is benign. That is why the naming scheme in `dataset/actors/` is load-bearing rather than
cosmetic.

The benign half matters as much as the attack half. It is roughly 73% real managed-AKS
infrastructure traffic, plus native controllers, plus **three real operators deployed on purpose** —
cert-manager, ArgoCD and kube-prometheus. Without them, "reads secrets" and "creates
clusterrolebindings" would be perfect attack signatures by accident, and the model would learn a
signature instead of a behaviour.

Some things the collection had to get right, each learned the hard way:

- **Window on the authenticated identity, not the impersonated one.** Keying on the victim scatters
  an impersonation attack across the identities it borrows and hides it completely.
- **Split on tool, not at random.** A random split let the model score ~100% on escalation while
  actually having memorised the density of our scripts: 6.4 secrets per window synthetic against 0.27
  for Stratus.
- **Regenerate templated classes with real behavioural variation.** The first impact class ran one
  deterministic deletion loop, so 40% of held-out windows were byte-identical to training ones and
  recall read 100%. Regenerated with six distinct profiles, the honest number is 67%. The fix is more
  variation, not dropping the inconvenient case.
- **Collapse identical trajectories before counting N.** Stratus reuses the same module across
  sessions; counting session × identity pairs inflated N, and a Wilson bound assumes independent
  trials.

The full datasheet (Gebru format, with per-version changelog) and the MITRE technique mapping are in
[docs/dataset/](docs/dataset/) — both still in Romanian, as thesis deliverables.

---

## Layout

```
src/
  cluster/aks/        provision AKS, Log Analytics, the kube-audit diagnostic setting
  dataset/
    actors/           create the benign and attacker identities, deploy the real operators
    attacks/          one script per attack scenario; each records its session boundaries
    tools/            runs of third-party tooling (Stratus, Peirates, rakkess)
    export/           Log Analytics -> windows -> features -> CSV
    reference/        the dataset itself
  model/
    train/            train_v2.py (held-out evaluation), train_production.py (the deployed model)
    train/flow/       the network-flow models
    eval/             ablations, diagnostics, the operational test
    artifacts/        classifier.json + config, mounted straight into the service
  service/
    audit/            the detector
    adapter/          Log Analytics -> /predict/raw (AKS)
    streamer/         audit.log -> /predict (self-managed)
    flow/             the flow detector and its Prometheus exporter
    correlator/       offline alert correlation
  deploy/             images, manifests, deploy scripts
  observability/      Prometheus, Alertmanager, Grafana, MailHog
  demo/               end-to-end walkthrough

docs/                 report material, figures, tables, the datasheet, reference papers
releases/             frozen deliverable snapshots
archive/              earlier generations of the project (see below)
data/                 datasets, trained models, captures - not in git
```

---

## Running it

The Python environment is pinned in `requirements-detection-lock.txt`. On an Intel Mac, torch pins to
2.2.2 and numpy must stay below 2.

Nothing below needs a cluster except the deploy and collection steps — the evaluation runs from the
committed CSV.

```bash
source detection/bin/activate

# reproduce the reported numbers (deterministic, random_state=0 throughout)
python src/model/train/train_v2.py                    # per-episode table with Wilson bounds
python src/model/eval/eval_model_only_standalone.py   # ROC / PR / recall@FPR / calibration
python src/model/eval/test_productie.py 1             # operational test at FPR 1%

# retrain the deployed model
python src/model/train/train_production.py
```

On a cluster:

```bash
bash src/cluster/aks/setup_aks.sh          # AKS + Log Analytics + audit diagnostic  (~10 min, costs money)
bash src/deploy/scripts/deploy_obs_aks.sh  # detector + adapter + observability       (~5 min)
./src/demo/run_demo_aks.sh --status        # what is actually running
./src/demo/run_demo_aks.sh --attack        # launch real attacks, watch Grafana
```

Rebuilding the dataset:

```bash
bash src/dataset/actors/setup_actors.sh
bash src/dataset/actors/deploy_operators.sh
bash src/dataset/attacks/attack_wilson_push.sh        # and the other attack_*.sh
# wait ~5 min for Log Analytics ingestion
(cd src/dataset/export && python export_v2.py)
```

This reproduces the **pipeline**, not the CSV. The audit stream carries real timing and real
infrastructure chatter, so a fresh collection is comparable but never byte-identical. That is
expected from a managed cluster, and the reason the CSV is committed as the reference.

Tear down when done: `az group delete -n intusion-detection-project --yes --no-wait`.

---

## How it got here

Three generations, kept in `archive/` because the dead ends are part of the argument.

**`archive/2025-flow-based-ids/`** — network-flow IDS on CICIDS2017 and pcap captures, an MLP
baseline, and the dataset survey that concluded no Kubernetes-specific dataset existed. That
conclusion is what started everything after it.

**`archive/2026-flow-retraining/`** — retraining on BCCC Cloud DDoS 2024 and the ITU set: XGBoost,
LightGBM, DistilBERT over flows rendered as text, held-out-day and cross-dataset evaluation. The
surviving output is the flow detector still shipping in `src/service/flow/`.

**`archive/audit-v1-transformer/`** — the first audit-plane attempt: a kind cluster, a sequence
Transformer over `verb:resource:subresource` tokens, and the first AKS collections. It reported
F1 0.934 and ROC-AUC 0.993, then transferred to real cloud traffic at an 18% false-positive rate.
The domain shift, and the discovery that "recon" detection was really `n_list` overfitting, is why
the current system uses behavioural features on windows rather than token sequences.

**`archive/audit-v2-hybrid-ablations/`** — the generation that shipped as a classifier plus six
deterministic rules (severity overlay, recon, mass-delete, workload-hijack, persistence, unknown
kube-system identity). The rules existed because the classifier failed cleanly on tactics it had
never seen: on Stratus persistence the classifier caught 11% of episodes and the
dedicated rule caught 89%. They were removed in v2.6 in
favour of a single auditable model with a stated scope. `train_v2.py` still evaluates them, so the
trade-off can be read off directly; `archive/notes/` holds the status documents from that period.

---

## Limitations

Stated plainly, because they bound what the results mean:

- **Metadata-level audit only.** No request or response bodies, so anything that depends on payload
  content is invisible.
- **One cluster, one operator, a short collection window.** No temporal disjunction, no cross-cluster
  validation. False-positive rates measured against noisier production traffic would likely be worse.
- **Benign traffic comes from a single generator.** A high AUC partly reflects synthetic-versus-tool
  separation, not only attack-versus-benign.
- **Small N per held-out class** — as low as one distinct episode for Peirates. Hence Wilson bounds
  rather than point estimates.
- **The trust boundary is a real hole.** The rule-based generation exempted allowlisted
  infrastructure identities and could catch a *fabricated* kube-system service account. A *genuine*
  controller whose token was stolen still gets through. Closing that needs a per-identity behavioural
  baseline, not a name list.

Defensible claim: a reference dataset, a reproducible pipeline, and a tool-disjoint generalisation
study for detection on the Kubernetes audit plane. Not: a benchmark, or a validated multi-tactic
detector.
