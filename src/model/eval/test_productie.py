#!/usr/bin/env python3
"""Operational test: does the deployed logic catch an attack run, not a window.

Per-window metrics flatter the model. What an operator cares about is whether a whole attack run
gets flagged, so this counts a run as detected when at least K windows cross the threshold - the
same K the service uses. Precision and false-positive rate come from the benign control runs.
"""
import csv, numpy as np, xgboost as xgb
from collections import defaultdict
from pathlib import Path
DS = Path(__file__).resolve().parents[3] / "src/dataset/reference/ref_v2_all.csv"
OLD=["forbid_ratio","n_forbid","n_events","n_distinct_resource","n_distinct_verb","n_distinct_ns","n_secrets","n_exec","n_rbac","n_create","n_delete","n_list","n_4xx","n_selfreview","selfreview_ratio"]
NEW=["has_secret","has_exec","has_rbac_write","has_crb","has_forbid","secret_rate","rbac_rate","create_rate","secret_ns","severity","cum_secrets","cum_rbac_w","cum_exec","cum_crb","has_impersonation","n_distinct_impersonated","n_create_workload","has_csr","has_tokenreq"]
FEAT=[c for c in OLD+NEW if c not in ("n_list","n_create_workload")]
LAT_TR={"adversary-lateral","adversary-lat-1","adversary-lat-2"}; ESCV_TR={"adversary-escv-1","adversary-escv-2","adversary-escv-3"}
CRED_TR={"adversary-creddump-1","adversary-creddump-2"}; PERSIST_TR={"adversary-persistsyn-1","adversary-persistsyn-2"}
K=2  # hysteresis: a run counts as detected once two windows cross the threshold
def uid(r): return r["user"].split(":")[-1]
def is_recon(u): return "recon-sa" in u or "redteam-rakkess" in u
def is_atk(r): return r["label"]=="1"
def fv(r): return [float(r[c]) for c in FEAT]
def vec(r): return tuple(round(float(r[c]),4) for c in FEAT)
def part(r):
    t=r["tool"]; s=int(r["session"]); u=uid(r)
    if t=="credsyn": return "train" if u in CRED_TR else "credsyn_eval"
    if t=="persistsyn": return "train" if u in PERSIST_TR else "persistsyn_eval"
    if t=="rakkess": return "recon_eval"
    if t in ("stratus","peirates","lowslow","persistence","lateralext","compromised"): return t+"_eval"
    if t=="lateral": return "train" if u in LAT_TR else "lateral_eval"
    if t=="escv": return "train" if u in ESCV_TR else "escv_eval"
    if t in ("impact","evasion"): return "drop"
    if is_recon(u): return "recon_eval" if s in (5,6) else "x"
    if s in (1,2,3,4): return "train"
    if s in (5,6): return "test"
    return "train"
rows=list(csv.DictReader(open(DS)))
EVALVECS={vec(r) for r in rows if part(r) in {"stratus_eval","peirates_eval","lateral_eval","escv_eval","lateralext_eval","persistence_eval","recon_eval","credsyn_eval","persistsyn_eval"} and is_atk(r)}
SD={"impact","evasion","compromised","lowslow"}
seen=set();X=[];y=[]
for r in rows:
    if part(r)!="train" or is_recon(uid(r)): continue
    if r["tool"] in SD and is_atk(r): continue
    if is_atk(r) and vec(r) in EVALVECS: continue
    k=(vec(r),r["label"])
    if k in seen: continue
    seen.add(k);X.append(fv(r));y.append(1 if is_atk(r) else 0)
clf=xgb.XGBClassifier(n_estimators=200,max_depth=4,learning_rate=0.1,scale_pos_weight=11,eval_metric="logloss",random_state=0).fit(np.array(X),np.array(y))
def proba(rs): return clf.predict_proba(np.array([fv(r) for r in rs]))[:,1]
ben=[r for r in rows if part(r)=="test" and not is_atk(r)]
bs=proba(ben)
import sys
FPR=float(sys.argv[1]) if len(sys.argv)>1 else 5.0   # false-alarm budget, in percent
thr=float(np.percentile(bs,100-FPR))

# Attack runs, grouped by (tactic, session, identity)
TAC={"escv_eval":"Privilege Escalation","lateral_eval":"Lateral Movement","credsyn_eval":"Credential Access",
     "persistsyn_eval":"Persistence","peirates_eval":"Priv-Esc (Peirates, external)","stratus_eval":"Cred-Access (Stratus, external)",
     "lateralext_eval":"Lateral (Stratus, external)","persistence_eval":"Persistence (Stratus, external)","recon_eval":"Recon (rakkess)"}
ep=defaultdict(list)
for r in rows:
    p=part(r)
    if p in TAC and is_atk(r): ep[(TAC[p],int(r["session"]),uid(r))].append(r)
res=defaultdict(lambda:[0,0])   # tactic -> [detected, total]
for (tac,s,u),ws in ep.items():
    det = int((proba(ws)>=thr).sum())>=K
    res[tac][1]+=1; res[tac][0]+=int(det)

# Benign control runs, grouped by (session, identity)
bep=defaultdict(list)
for r in ben: bep[(int(r["session"]),uid(r))].append(r)
fp=tn=0
for (s,u),ws in bep.items():
    det=int((proba(ws)>=thr).sum())>=K
    fp+=int(det); tn+=int(not det)

print(f"Per-run detection at FPR={FPR:.0f}% (threshold {thr:.4f}), K={K} windows.")
print("="*78)
print(f"{'Tactic':32}{'runs':>8}{'caught':>8}{'RECALL':>9}")
print("-"*78)
order=["Privilege Escalation","Priv-Esc (Peirates, external)","Lateral Movement","Lateral (Stratus, external)",
       "Credential Access","Cred-Access (Stratus, external)","Persistence","Persistence (Stratus, external)","Recon (rakkess)"]
tot_tp=tot_n=0
for tac in order:
    if tac not in res: continue
    d,n=res[tac]; tot_tp+=d; tot_n+=n
    print(f"{tac:32}{n:>8}{d:>8}{100*d/n:>8.0f}%")
print("-"*78)
prec = 100*tot_tp/(tot_tp+fp) if (tot_tp+fp) else 0
print(f"{'TOTAL':32}{tot_n:>8}{tot_tp:>8}{100*tot_tp/tot_n:>8.0f}%")
print(f"\nBenign control runs: {fp+tn}  ->  false alarms: {fp}  ({100*fp/(fp+tn):.0f}%)")
print(f"Precision: {prec:.0f}%")
print("\nThe tools scored here are not in the training set, so this measures generalisation.")
print("Pass a different budget as the first argument, e.g. test_productie.py 1")
