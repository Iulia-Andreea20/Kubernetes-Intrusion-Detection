# How the Runtime-IDS Dataset Was Built

This document explains, step by step, how `data/audit_events.csv` and the
feature files were produced. It is written to be understandable without prior
Kubernetes knowledge, and it doubles as the draft of the **Dataset Generation**
chapter of Report 2.

---

## 1. Why we build our own dataset

A supervised intrusion-detection model needs labelled examples: activity marked
as *attack* or *benign*. For Kubernetes **API audit logs** there is no suitable
public dataset, so we generate one in a controlled test cluster.

- **Advantage:** we have perfect ground truth — we run the attacks ourselves, so
  we know the exact time each one happened.
- **Disadvantage:** the data is synthetic. This is stated honestly in
  Section 10 (Limitations) and the thesis Discussion chapter.

The principle behind the whole design: **manufacture activity, record it, label
it by time.**

---

## 2. The method in one picture

```
[1] kind cluster + audit logging ON      cluster/
        │   every API request -> one JSON line in audit-logs/audit.log
        ▼
[2] generate activity                    attacks/
        benign workload  +  6 attack scenarios
        each attack writes its exact start/end time to data/labels.jsonl
        ▼
[3] collect + label                      collect/collect_audit.py
        read the log, attach label 0 (benign) / 1 (attack) to every event
        -> data/audit_events.csv
        ▼
[4] featurize                            features/featurize.py
        -> data/features_tabular.csv  (for tree models)
        -> data/sequences.jsonl       (for the deep model)
```

---

## 3. Step 1 — the test cluster with audit logging

`cluster/setup_kind.sh` builds a throwaway one-node Kubernetes cluster with
**kind** (Kubernetes-in-Docker).

The key part is the **audit log**. The Kubernetes API server is the front door
of the cluster — every action is a request to it. When audit logging is on, the
API server writes **one JSON line per request**: who made it, what verb
(`get`/`create`/`delete`/...), on what resource, in what namespace, and whether
it succeeded. That log is our raw data.

`cluster/audit-policy.yaml` decides *what* is logged and in *how much detail*:

- **Sensitive resources** — pods, secrets, RBAC objects, `exec`, token requests —
  are logged at `RequestResponse` level, meaning the **full request body** is
  included. This matters: it is the only way to see *inside* a request (e.g.
  whether a pod is privileged — see Section 7).
- **Routine resources** are logged at `Metadata` level (no body).
- **Health-check noise** (`/healthz`, `/metrics`, ...) is dropped.

The log is written inside the cluster and bind-mounted out to the host file
`audit-logs/audit.log`.

---

## 4. Step 2 — generating activity

We produce two kinds of activity.

### 4.1 Benign activity (`attacks/benign_workload.sh`)

- `benign_round` — ordinary operations: deploy an app, inspect it, read logs,
  scale it up and down, list namespaces.
- `benign_admin_round` — **legitimate versions of the sensitive actions** the
  attacks also use: a single debug `exec`, a scoped secret read, a namespaced
  least-privilege Role, a read-only ClusterRole, a token for the app's own
  service account, a plain pod. Why this exists is explained in Section 8 — it
  is the most important design decision in the whole dataset.

### 4.2 Attack scenarios (`attacks/attack_scenarios.sh`)

Six scenarios, each mapped to a technique in **MITRE ATT&CK for Containers**
(the industry catalogue of attacker behaviour):

| Scenario | What it does | MITRE |
|----------|--------------|-------|
| `recon` | Lists pods, secrets, nodes, roles, permissions across all namespaces | T1613 |
| `exec_abuse` | Runs a burst of recon commands inside a running container | T1609 |
| `rbac_escalation` | Creates a cluster-wide **wildcard** ClusterRole + binding | T1078 |
| `secret_access` | Dumps every secret in every namespace, including `kube-system` | T1552 |
| `sa_token_abuse` | Requests service-account tokens, including in `kube-system` | T1528 |
| `malicious_pod` | Deploys a **privileged**, host-mounting pod (container escape) | T1610 |

Each scenario is **repeatable** (unique object names, self-cleanup) so it can be
run many times, and each records its precise start/end time.

---

## 5. Step 3 — orchestration and timing (`attacks/run_dataset.sh`)

The orchestrator:

1. Writes `data/run_start` — a timestamp marking the start of this dataset run.
2. Loops `ROUNDS` times (default 12). Each round runs, **strictly in order**:
   `benign_round` → `benign_admin_round` → the 6 attacks → `benign_round` →
   `benign_admin_round`.
3. Every attack appends a line to `data/labels.jsonl` recording its
   `attack_type`, MITRE id, and exact `start`/`end` timestamps (microsecond
   precision — see the note below).

**Benign and attack phases never overlap in time.** This is what makes labelling
by time window unambiguous (Section 6).

> **A bug we fixed:** the first version used `date`, which on macOS has only
> 1-second resolution. Fast attacks then had `start == end` — a zero-width
> window that no event could fall inside, so nothing got labelled. The fix was
> microsecond-precision timestamps from Python.

---

## 6. Step 4 — collection and labelling (`collect/collect_audit.py`)

The collector reads `audit-logs/audit.log` and produces `data/audit_events.csv`,
one row per event. The **labelling rule**:

> An event is **label = 1 (attack)** if its timestamp falls inside an attack
> window from `labels.jsonl` **and** it was issued by a non-system user.
> Otherwise it is **label = 0 (benign)**.

Two details make this valid:

- **System controllers are always benign.** Kubernetes' own controllers
  (`system:...` users) generate constant background traffic during every
  window; excluding them prevents that traffic from being mislabelled.
- **Only events after `run_start` are kept.** Events from earlier runs or from
  cluster start-up are discarded, so re-running the generator gives a clean
  dataset without recreating the cluster.

---

## 7. Step 5 — from events to features (`features/featurize.py`)

Some attacks cannot be told apart from benign activity using only the *type* of
event. Two cases need information from the **request body** (available because
those resources are audited at `RequestResponse` level):

- **`pod_privileged`, `pod_host_path`, `pod_host_pid`, ...** — a benign pod and a
  container-escape pod are both "create pod"; only the security context in the
  body reveals the difference.
- **`rbac_wildcard`** — a benign Role and an escalation Role are both "create
  role"; only the rules in the body reveal that one grants `*` (everything).

`featurize.py` then builds **two views** of the same events:

- **Tabular** (`features_tabular.csv`, 77 columns) — for the tree models:
  one-hot of verb/resource/namespace, identity flags, response-code flags, the
  body features above, and **behavioural rate features** (how many calls,
  how many distinct resources, how many errors this user made in the last 5 s
  and 60 s). The rate features are the real behavioural signal.
- **Sequence** (`sequences.jsonl` + `vocab.json`) — for the deep model: each
  event becomes a `verb:resource:subresource` token, and the feature is the
  window of the last 20 tokens by the same user (the DeepLog / LogBERT style).

Row *i* of the tabular file and line *i* of the sequence file describe the
**same event**, so the two model families are directly comparable.

---

## 8. The most important design decision

A first version of the benign workload only did harmless things — it never ran
`exec`, never read secrets, never created RBAC. That makes the dataset **invalid**:
event types like `exec` would appear *only* in attacks, so a model could score
~99% by learning the trivial rule *"exec = attack"*. A real admin runs `exec` to
debug pods all the time — such a model would flag them constantly.

The fix (`benign_admin_round`): the benign workload performs **legitimate
versions of every sensitive action** an attack uses. Attack and benign activity
then differ by **scope, rate, and intent** — not by action type:

| | benign version | attack version |
|---|---|---|
| exec | one innocuous command | a burst of recon commands |
| secrets | the app's own namespace | every namespace incl. `kube-system` |
| RBAC | namespaced, least-privilege | cluster-wide, wildcard |
| token | the app's own service account | `kube-system` service accounts |
| pod | a plain pod | a privileged, host-mounting pod |

This forces the model to learn **real detection**. We verified that every
sensitive event type now appears in *both* classes.

---

## 9. Dataset statistics (final run, `ROUNDS=40`)

- **7,396 events** — 1,666 attack / 5,730 benign (~23% attack)
- **6 attack types** — container_exec (600), discovery (388),
  privilege_escalation (258), credential_theft (211), token_theft (129),
  container_escape (80)
- **77 tabular features**; **119-token** sequence vocabulary, window length 20

---

## 10. Limitations (state these in the thesis)

- **Synthetic** — generated in a test cluster, not captured from production.
- **One small single-node cluster**, one benign workload profile.
- **Known, scripted attacks** — good for supervised detection, but the model is
  not evaluated against novel/unseen attack variants.
- **Class balance (~23% attack) is not realistic** — real clusters see far fewer
  attacks. The evaluation therefore also reports false-positive rate, which is
  what matters at realistic attack prevalence.
- **Audit log only** — host/syscall behaviour (crypto-mining, reverse shells)
  is not visible here; that is the job of the Falco/eBPF arm (evaluated but **not
  applicable on the AKS `5.15-azure` kernel** — see `RAPORT_FINAL_IDS_AUDIT.md §1`).

---

## 11. How to regenerate or scale up

```bash
cd runtime_ids
./cluster/setup_kind.sh                 # once (build the cluster)
ROUNDS=40 ./attacks/run_dataset.sh      # more rounds = more attack examples
python3 collect/collect_audit.py        # -> data/audit_events.csv
python3 features/featurize.py           # -> features_tabular.csv, sequences.jsonl
```

For the final thesis numbers, use a larger `ROUNDS` (e.g. 40–60) so each attack
type has several hundred examples.
