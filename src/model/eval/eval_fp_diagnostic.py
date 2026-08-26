#!/usr/bin/env python3
"""Which added attack class is responsible for the false positives, and why.

Starts from a classifier trained on escalation only, then adds one class at a time and reports how
much the false-positive rate moves and which benign identities start firing. This is how the miner
windows in the impact class were caught: they were teaching the model that workload creation is an
attack, which fires on benign AKS node creation.
"""
import csv, numpy as np, xgboost as xgb
from collections import defaultdict
from pathlib import Path
DS = str(Path(__file__).resolve().parents[3] / "src/dataset/reference/ref_v2_all.csv")
OLD=["forbid_ratio","n_forbid","n_events","n_distinct_resource","n_distinct_verb","n_distinct_ns","n_secrets","n_exec","n_rbac","n_create","n_delete","n_list","n_4xx","n_selfreview","selfreview_ratio"]
NEW=["has_secret","has_exec","has_rbac_write","has_crb","has_forbid","secret_rate","rbac_rate","create_rate","secret_ns","severity","cum_secrets","cum_rbac_w","cum_exec","cum_crb","has_impersonation","n_distinct_impersonated"]
FEAT=[c for c in OLD+NEW if c!="n_list"]
LAT_TR={"adversary-lateral","adversary-lat-1","adversary-lat-2"}
IMP_TR={"adversary-impact","adversary-imp-1"}
EVA_TR={"adversary-evasion","adversary-eva-1"}
HO={"adversary-lateral2","adversary-lat-3","adversary-imp-2","adversary-imp-3","adversary-eva-2","adversary-eva-3"}
rows=list(csv.DictReader(open(DS)))
def uid(r): return r["user"].split(":")[-1]
def isr(u): return "recon-sa" in u or "redteam-rakkess" in u
def fv(r): return [float(r[c]) for c in FEAT]
def vec(r): return tuple(round(float(r[c]),4) for c in FEAT)
def base_part(r):  # baseline: escalation only, the newer classes stay out of train
    t=r["tool"]; s=int(r["session"]); u=uid(r)
    if t=="rakkess": return "recon"
    if t in ("stratus","peirates","lowslow"): return "esc_ho"
    if t in ("lateral","impact","evasion"): return "newclass"
    if isr(u): return "recon" if s in (5,6) else "rx"
    if s in (1,2,3,4): return "train"
    if s in (5,6): return "test"
    return "train"
TR={"lateral":LAT_TR,"impact":IMP_TR,"evasion":EVA_TR}
def build(extra):  # extra in {None, "lateral", "impact", "evasion"}
    seen=set(); X=[]; y=[]
    for r in rows:
        p=base_part(r); t=r["tool"]; u=uid(r)
        use=False
        if p=="train" and not isr(u): use=True
        if extra and t==extra and u in TR[extra]: use=True
        if not use: continue
        k=(vec(r),r["label"])
        if k in seen: continue
        seen.add(k); X.append(fv(r)); y.append(int(r["label"]))
    X=np.array(X); y=np.array(y); spw=max(1.0,(y==0).sum()/max(1,(y==1).sum()))
    return xgb.XGBClassifier(n_estimators=200,max_depth=4,learning_rate=0.1,scale_pos_weight=spw,eval_metric="logloss",random_state=0).fit(X,y),int(y.sum())
def proba(clf,rs): return clf.predict_proba(np.array([fv(r) for r in rs]))[:,1] if rs else np.array([])

# Benign episodes, plus held-out recall for whichever class was added
def evalc(clf,extra):
    # Per-identity episode false positives on the benign test set
    bep=defaultdict(list)
    for r in rows:
        if base_part(r)=="test" and r["label"]=="0" and not("ci-deployer" in uid(r) or "compliance" in uid(r)):
            bep[(r["session"],uid(r))].append(r)
    fp=[];
    for (s,u),rs in bep.items():
        P=proba(clf,rs)
        if int((P>=0.5).sum())>=2:
            wn=[r for r,p in zip(rs,P) if p>=0.5]
            mx=max(P)
            # which feature dominates in the windows that fired
            feat={c:round(np.mean([float(r[c]) for r in wn]),1) for c in ["n_delete","n_create","n_secrets","has_impersonation","severity","n_distinct_verb"]}
            fp.append((u,len(wn),round(float(mx),2),feat))
    # Window-level FP over all benign traffic, and separately over the deleting controllers
    allben=[r for r in rows if r["label"]=="0"]
    Pall=proba(clf,allben); wfp=int((Pall>=0.5).sum())
    delctrl=[r for r in rows if r["label"]=="0" and float(r["n_delete"])>=3]
    Pdel=proba(clf,delctrl) if delctrl else np.array([])
    dfp=int((Pdel>=0.5).sum()) if len(Pdel) else 0
    # held-out recall for the added class
    horec=None
    if extra:
        he=defaultdict(list)
        for r in rows:
            if r["tool"]==extra and uid(r) in HO: he[(r["session"],uid(r))].append(r)
        det=sum(1 for rs in he.values() if int((proba(clf,rs)>=0.5).sum())>=2)
        horec=(det,len(he))
    return fp,wfp,len(allben),dfp,len(delctrl),horec

print("="*96)
print(" False-positive diagnostic: escalation baseline plus one class at a time")
print("="*96)
for extra in [None,"lateral","impact","evasion"]:
    clf,p=build(extra); fp,wfp,nb,dfp,ndel,hor=evalc(clf,extra)
    tag="baseline (escalation only)" if not extra else f"baseline + {extra}"
    print(f"\n>> {tag}  (train poz={p})")
    print(f"   episode FP on benign: {len(fp)}/57   |   window FP on all benign: {wfp}/{nb} ({100*wfp/nb:.2f}%)   |   window FP on deletion windows: {dfp}/{ndel}")
    if hor: print(f"   held-out recall {extra}: {hor[0]}/{hor[1]}")
    for u,nw,mx,feat in fp:
        print(f"      FP -> {u}: {nw} windows, maxP={mx}, {feat}")
