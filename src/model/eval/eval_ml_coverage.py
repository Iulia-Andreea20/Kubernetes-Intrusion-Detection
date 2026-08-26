#!/usr/bin/env python3
"""Can the classifier learn lateral, impact and evasion at all, if we put them in training?

Splits on identity rather than session - half the identities of each class train, the rest are
held out - so the answer is about generalisation to new actors, not memorisation. Recon stays
out: putting it in the classifier blows up the false-positive rate.
"""
import csv, numpy as np, xgboost as xgb
from collections import defaultdict
from pathlib import Path
DS = str(Path(__file__).resolve().parents[3] / "src/dataset/reference/ref_v2_all.csv")
OLD=["forbid_ratio","n_forbid","n_events","n_distinct_resource","n_distinct_verb","n_distinct_ns","n_secrets","n_exec","n_rbac","n_create","n_delete","n_list","n_4xx","n_selfreview","selfreview_ratio"]
NEW=["has_secret","has_exec","has_rbac_write","has_crb","has_forbid","secret_rate","rbac_rate","create_rate","secret_ns","severity","cum_secrets","cum_rbac_w","cum_exec","cum_crb","has_impersonation","n_distinct_impersonated"]
FEAT=[c for c in OLD+NEW if c!="n_list"]
rows=list(csv.DictReader(open(DS)))
def uid(r): return r["user"].split(":")[-1]
def is_recon(u): return "recon-sa" in u or "redteam-rakkess" in u
def fv(r): return [float(r[c]) for c in FEAT]
def vec(r): return tuple(round(float(r[c]),4) for c in FEAT)
# identity split for the newer classes
LAT_TR={"adversary-lateral","adversary-lat-1","adversary-lat-2"}; LAT_HO={"adversary-lateral2","adversary-lat-3"}
IMP_TR={"adversary-impact","adversary-imp-1"};                    IMP_HO={"adversary-imp-2","adversary-imp-3"}
EVA_TR={"adversary-evasion","adversary-eva-1"};                   EVA_HO={"adversary-eva-2","adversary-eva-3"}
def split_of(r):
    t=r["tool"]; s=int(r["session"]); u=uid(r)
    if t=="rakkess": return ("recon_ho",None)
    if t=="stratus": return ("train",None)
    if t=="peirates": return ("ho","esc:Peirates")
    if t=="lowslow":  return ("ho","esc:lowslow")
    if t=="lateral":  return ("train" if u in LAT_TR else "ho","lateral") if (u in LAT_TR or u in LAT_HO) else ("ho","lateral")
    if t=="impact":   return ("train" if u in IMP_TR else "ho","impact") if (u in IMP_TR or u in IMP_HO) else ("ho","impact")
    if t=="evasion":  return ("train" if u in EVA_TR else "ho","evasion") if (u in EVA_TR or u in EVA_HO) else ("ho","evasion")
    if is_recon(u): return ("recon_ho",None) if s in (5,6) else ("train_excl",None)
    if s in (1,2,3,4): return ("train",None)
    if s in (5,6): return ("test","esc:in-dist" if r["label"]=="1" else ("benign-cani" if ("ci-deployer" in u or "compliance" in u) else "benign-normal"))
    return ("train",None)  # benign background from the tool sessions

def build_train(include_new):
    seen=set(); X=[]; y=[]
    for r in rows:
        sp,_=split_of(r)
        if sp!="train": continue
        if is_recon(uid(r)): continue
        t=r["tool"]
        if (not include_new) and t in ("lateral","impact","evasion"): continue
        k=(vec(r),r["label"])
        if k in seen: continue
        seen.add(k); X.append(fv(r)); y.append(int(r["label"]))
    X=np.array(X); y=np.array(y); spw=max(1.0,(y==0).sum()/max(1,(y==1).sum()))
    clf=xgb.XGBClassifier(n_estimators=200,max_depth=4,learning_rate=0.1,scale_pos_weight=spw,eval_metric="logloss",random_state=0).fit(X,y)
    return clf,X.shape[0],int(y.sum())

# group held-out attack and benign episodes
def eval_clf(clf):
    epi=defaultdict(list)   # (category, session, uid) -> windows
    ben=defaultdict(list)
    for r in rows:
        sp,catg=split_of(r)
        if sp=="ho" and catg: epi[(catg,r["session"],uid(r))].append(r)
        elif sp=="test" and catg and catg.startswith("benign"): ben[(catg,r["session"],uid(r))].append(r)
        elif sp=="test" and catg=="esc:in-dist": epi[(catg,r["session"],uid(r))].append(r)
    def rec(rs): P=clf.predict_proba(np.array([fv(r) for r in rs]))[:,1]; return int((P>=0.5).sum())>=2
    out=defaultdict(lambda:[0,0])
    for (catg,s,u),rs in epi.items(): out[catg][1]+=1; out[catg][0]+=int(rec(rs))
    fp=defaultdict(lambda:[0,0])
    for (catg,s,u),rs in ben.items(): fp[catg][1]+=1; fp[catg][0]+=int(rec(rs))
    # Also measure FPR on the deleting controllers: that is where impact/evasion realistically hurt
    delctrl=defaultdict(list)
    ALLOWDEL=["aksService","masterclient","generic-garbage-collector","namespace-controller"]
    for r in rows:
        if r["label"]=="0" and any(a in r["user"] for a in ALLOWDEL) and float(r["n_delete"])>=3:
            delctrl[(uid(r),r["session"])].append(r)
    dfp=[0,0]
    for k,rs in delctrl.items(): dfp[1]+=1; dfp[0]+=int(rec(rs))
    return out,fp,dfp

print("="*92)
print(" EXPERIMENT: ML pe lateral/impact/evasion (split pe IDENTITATE). Recall held-out pe EPISOD.")
print("="*92)
for tag,inc in [("baseline: escalation only",False),("plus lateral/impact/evasion",True)]:
    clf,n,p=build_train(inc); out,fp,dfp=eval_clf(clf)
    print(f"\n>> {tag}: {n} training windows ({p} positive)")
    imp=sorted(zip(FEAT,clf.feature_importances_),key=lambda x:-x[1])[:6]
    print("   importanta:", {k:round(float(v),2) for k,v in imp})
    def pc(x): return f"{100*x[0]/x[1]:.0f}% ({x[0]}/{x[1]})" if x[1] else "-"
    for c in ["esc:in-dist","esc:Peirates","esc:lowslow","lateral","impact","evasion"]:
        print(f"     {c:16} recall held-out: {pc(out[c])}")
    print(f"     FPR benign-normal: {pc(fp['benign-normal'])} | benign-cani: {pc(fp['benign-cani'])} | controllere-care-sterg: {pc(dfp)}")
