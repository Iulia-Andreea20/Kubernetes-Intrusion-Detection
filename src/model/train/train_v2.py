#!/usr/bin/env python3
"""Held-out evaluation of the audit detector: the numbers reported in the thesis come from here.

This is the honest pipeline, not the production one. It trains on a subset and scores the rest,
splitting three different ways depending on what a class can support:

  tool-disjoint      escalation trains on synthetic identities only; every real third-party tool
                     (Stratus, Peirates) is held out, so a good score means the model learned the
                     technique rather than the script.
  identity-disjoint  lateral / impact / evasion have no external tool available, so half the
                     identities train and half are held out.
  behaviour-disjoint the regenerated classes (escv, impv, evav) split on behaviour profile, which
                     is stricter than splitting on identity alone.

It also still evaluates the six support rules that shipped up to v2.4. The deployed model is pure
XGBoost now, so read the classifier column as the system and the rest as the history.
"""
import csv
from collections import defaultdict, Counter
import numpy as np, xgboost as xgb
from pathlib import Path
DS = Path(__file__).resolve().parents[3] / "src/dataset/reference/ref_v2_all.csv"
OLD=["forbid_ratio","n_forbid","n_events","n_distinct_resource","n_distinct_verb","n_distinct_ns","n_secrets","n_exec","n_rbac","n_create","n_delete","n_list","n_4xx","n_selfreview","selfreview_ratio"]
NEW=["has_secret","has_exec","has_rbac_write","has_crb","has_forbid","secret_rate","rbac_rate","create_rate","secret_ns","severity","cum_secrets","cum_rbac_w","cum_exec","cum_crb","has_impersonation","n_distinct_impersonated","n_create_workload","has_csr","has_tokenreq"]
# n_list is dropped because the model was using it as a density crutch: it learned "attack means
# lots of listing", which collapses on a paced-out attacker. The other three are rule-only signals.
FEAT=[c for c in OLD+NEW if c not in ("n_list","n_create_workload","has_csr","has_tokenreq")]
# Anchored allowlist: exact match or namespace prefix, never substring. Substring matching let an
# attacker sitting in `default`, or naming itself `sre-oncall-evil`, inherit the exemption.
ALLOW_EXACT={"ci-deployer","sre-oncall","devops-pipeline","platform-engineer","security-auditor","platform-admin",
       "aksService","readinessChecker","masterclient","hcpService","system:apiserver",
       "system:serviceaccount:default:compliance-scanner-sa"}
ALLOW_PREFIX=("system:serviceaccount:kube-system:","system:serviceaccount:monitoring:",
       "system:serviceaccount:cert-manager:","system:serviceaccount:argocd:","system:node:",
       "system:serviceaccount:falco:")
R_RECON=5; D_DEL=5; H_WL=1; K=2
LAT_TR={"adversary-lateral","adversary-lat-1","adversary-lat-2"}; LAT_HO={"adversary-lateral2","adversary-lat-3","adversary-lat-8","adversary-lat-9","adversary-lat-10"}
IMP_TR={"adversary-impv-1","adversary-impv-2","adversary-impv-3"}  # burst / multi-type / miner
IMP_HO={"adversary-impv-4","adversary-impv-5","adversary-impv-6","adversary-impv-11","adversary-impv-12","adversary-impv-13"}
ESCV_TR={"adversary-escv-1","adversary-escv-2","adversary-escv-3"} # forbid-trail / multi-ns-dump / rbac-create
ESCV_HO={"adversary-escv-4","adversary-escv-5","adversary-escv-6"} # exec-focus / single-ns-hoard / slow-mixed
EVA_TR={"adversary-evav-1","adversary-evav-2","adversary-evav-3"}
EVA_HO={"adversary-evav-4","adversary-evav-5","adversary-evav-6","adversary-evav-11","adversary-evav-12","adversary-evav-13"}

rows=list(csv.DictReader(open(DS)))
def uid(r): return r["user"].split(":")[-1]
def is_recon(u): return "recon-sa" in u or "redteam-rakkess" in u
def is_atk(r): return r["label"]=="1"
def allowed(u): return u in ALLOW_EXACT or u.startswith(ALLOW_PREFIX)
def fv(r): return [float(r[c]) for c in FEAT]
def vec(r): return tuple(round(float(r[c]),4) for c in FEAT)
def part(r):
    t=r["tool"]; s=int(r["session"]); u=uid(r)
    if t=="rakkess":  return "recon_eval"
    if t=="stratus":  return "stratus_eval"
    if t=="peirates": return "peirates_eval"
    if t=="lowslow":  return "lowslow_eval"
    if t=="lateral":  return "train" if u in LAT_TR else "lateral_eval"
    # The impv-*/evav-* identities are the regenerated, behaviourally varied runs; the older
    # template runs they replaced are dropped rather than evaluated, since they are near-clones.
    if t=="impact":   return "train" if u in IMP_TR else ("impact_eval" if "impv" in u else "drop")
    if t=="escv":     return "train" if u in ESCV_TR else "escv_eval"
    if t=="evasion":  return "train" if u in EVA_TR else ("evasion_eval" if "evav" in u else "drop")
    if t=="persistence": return "persistence_eval"
    if t=="lateralext":  return "lateralext_eval"
    if t=="compromised": return "compromised_eval"
    if is_recon(u):   return "recon_eval" if s in (5,6) else "train_recon_excl"
    if s in (1,2,3,4): return "train"
    if s in (5,6):     return "test"
    return "train"

# Feature-disjoint training set: drop from train any attack window byte-identical to a held-out
# one. Deduplicating only inside train still leaked, because different sessions of the same tactic
# produce identical feature vectors. train_production.py deliberately does not do this.
EVALPARTS={"stratus_eval","peirates_eval","lowslow_eval","lateral_eval","impact_eval","evasion_eval",
           "recon_eval","persistence_eval","lateralext_eval","escv_eval"}
EVALVECS={vec(r) for r in rows if part(r) in EVALPARTS and is_atk(r)}
# Identities the allowlist exempts AND that were actually observed behaving benignly. A fabricated
# service account in kube-system matches the prefix but is not in here, which is what the `anom`
# rule keys on: a pure rate rule cannot work, since benign controllers mass-delete faster than the
# attack does. An existing controller whose token was stolen still slips through.
KNOWN_ALLOW={r["user"] for r in rows if r["label"]=="0" and allowed(r["user"])}
seen=set(); Xtr,ytr=[],[]; episodes=defaultdict(list); n_leak=0
for r in rows:
    p=part(r); episodes[(p,r["session"],uid(r))].append(r)
    if p=="train" and not is_recon(uid(r)):
        # Impact means mass deletion. Training on the miner's workload-create windows made the
        # model fire on benign AKS node creation, so only the deletion windows count as positive.
        if r["tool"]=="impact" and is_atk(r) and not (float(r["n_delete"])>=1 and float(r["n_create"])==0): continue
        if is_atk(r) and vec(r) in EVALVECS: n_leak+=1; continue
        key=(vec(r),r["label"])
        if key in seen: continue
        seen.add(key); Xtr.append(fv(r)); ytr.append(1 if is_atk(r) else 0)
import os
Xtr=np.array(Xtr); ytr=np.array(ytr); spw=max(1.0,(ytr==0).sum()/max(1,(ytr==1).sum()))
# Cap the positive weight. Attack sessions drag in incidental control-plane benign traffic, which
# pushed spw from 10.75 to 13.27 and took false positives on benign infrastructure from 7% to 39%.
# How aggressive the model is should not depend on how much bystander traffic got collected.
SPW_CAP=float(os.environ.get("SPW_CAP","11"))
if SPW_CAP>0: spw=min(spw,SPW_CAP)
clf=xgb.XGBClassifier(n_estimators=200,max_depth=4,learning_rate=0.1,scale_pos_weight=spw,eval_metric="logloss",random_state=0).fit(Xtr,ytr)
def proba(rs): return clf.predict_proba(np.array([fv(r) for r in rs]))[:,1] if rs else np.array([])

# Episode-level detectors. All the rules exempt allowlisted identities except `anom`, because live
# testing showed the managed control plane does the flagrant things: masterclient creates
# clusterrolebindings, cainjector watches secrets across namespaces.
def ep_class(rs): return int((proba(rs)>=0.5).sum())>=K
def ep_F(rs,u):
    if allowed(u): return False
    return any((float(r["has_crb"])>=1 or float(r["has_exec"])>=1 or float(r["has_impersonation"])>=1 or (float(r["has_secret"])>=1 and float(r["secret_ns"])>=2)) for r in rs)
def ep_recon(rs,u):
    if allowed(u): return False
    return any(float(r["n_selfreview"])>=R_RECON for r in rs)
def ep_destruct(rs,u):
    if allowed(u): return False
    return any(float(r["n_delete"])>=D_DEL for r in rs)
def ep_hijack(rs,u):
    if allowed(u): return False
    return any(float(r["n_create_workload"])>=H_WL for r in rs)
def ep_persist(rs,u):
    if allowed(u): return False
    return any(float(r["has_csr"])>=1 or float(r["has_tokenreq"])>=1 for r in rs)
def ep_anom(rs,u):
    # Fires only on an allowlisted-by-prefix identity nobody has seen before, i.e. a service
    # account an attacker fabricated inside kube-system.
    if not allowed(u): return False
    if not u.startswith("system:serviceaccount:"): return False
    if u in KNOWN_ALLOW: return False
    return any(float(r["n_delete"])>=D_DEL or float(r["n_selfreview"])>=R_RECON or float(r["n_create_workload"])>=H_WL
               or float(r["has_csr"])>=1 or float(r["has_tokenreq"])>=1 for r in rs)

def catg_of(p,u,atk):
    M={"stratus_eval":"HELD-ext escalation, sparse (Stratus)","peirates_eval":"HELD-ext escalation, dense (Peirates)",
       "lowslow_eval":"HELD escalation, paced out (lowslow)","lateral_eval":"HELD-id lateral (impersonation)",
       "impact_eval":"HELD-id impact (deletion)","evasion_eval":"HELD-id defense evasion","recon_eval":"HELD recon (rakkess)",
       "persistence_eval":"HELD-ext persistence (Stratus)","lateralext_eval":"HELD-ext lateral token (Stratus)",
       "escv_eval":"HELD-id escalation, varied (synth)","compromised_eval":"HELD kube-system compromised (allowlisted)"}
    if p in M: return M[p]
    if p=="test": return ("IN-DIST escalation (synthetic)" if (atk and not is_recon(u)) else "IN-DIST recon-sa" if atk else
                          ("BENIGN can-i" if ("ci-deployer" in u or "compliance" in u) else "BENIGN normal"))
    return None

# Recall on windows the model has genuinely never seen. Without this, up to 19% of the evaluation
# windows were byte-identical to training ones and the headline numbers came out too high.
TRAINPOS={v for (v,lab) in seen if lab=="1"}
def ep_class_novel(rs):
    novel=[r for r in rs if vec(r) not in TRAINPOS]
    return ep_class(novel)
# Collapse byte-identical trajectories before counting N. Stratus reuses the same module across
# sessions, so counting session x identity pairs inflated N, and Wilson assumes independent trials.
cat=defaultdict(lambda: defaultdict(lambda: [0,0]))
catsig=defaultdict(set)
for (p,s,u),rs in episodes.items():
    catg=catg_of(p,u,is_atk(rs[0]))
    if not catg: continue
    sig=tuple(vec(r) for r in rs)
    if sig in catsig[catg]: continue
    catsig[catg].add(sig)
    fullu=rs[0]["user"]   # full username: the short uid misses the system:serviceaccount: prefixes
    naw=not allowed(fullu)
    m=ep_class(rs) and naw; mn=ep_class_novel(rs) and naw; f=ep_F(rs,fullu); rc=ep_recon(rs,fullu); d=ep_destruct(rs,fullu); hj=ep_hijack(rs,fullu); ps=ep_persist(rs,fullu); an=ep_anom(rs,fullu)
    full=m or f or rc or d or hj or ps or an; full_nov=mn or f or rc or d or hj or ps or an
    for rule,fn in [("clasif",m),("clasif_nov",mn),("F",f),("recon",rc),("destruct",d),("hijack",hj),("persist",ps),("anom",an),("FULL",full),("FULL_nov",full_nov)]:
        cat[catg][rule][1]+=1; cat[catg][rule][0]+=int(fn)

print(f">> train: {len(Xtr)} windows ({int(ytr.sum())} positive; recon excluded), {len(FEAT)} features. "
      f"Dropped {n_leak} attack windows byte-identical to held-out ones.")
print("   top importance:", {k:round(float(v),3) for k,v in sorted(zip(FEAT,clf.feature_importances_),key=lambda x:-x[1])[:6]})
ORDER=["IN-DIST escalation (synthetic)","HELD-id escalation, varied (synth)","HELD-ext escalation, dense (Peirates)","HELD-ext escalation, sparse (Stratus)",
       "HELD escalation, paced out (lowslow)","HELD-id lateral (impersonation)","HELD-id impact (deletion)","HELD-id defense evasion",
       "HELD-ext persistence (Stratus)","HELD-ext lateral token (Stratus)","HELD kube-system compromised (allowlisted)","IN-DIST recon-sa","HELD recon (rakkess)","BENIGN can-i","BENIGN normal"]
def wilson_lb(k,n,z=1.96):
    """Wilson 95% lower bound. With one or two episodes per class, a raw 100% means very little."""
    if n==0: return 0.0
    p=k/n; d=1+z*z/n
    return max(0.0,(p+z*z/(2*n)-z*np.sqrt(p*(1-p)/n+z*z/(4*n*n)))/d)
print("\n"+"="*150); print(" Per-episode detection, N = distinct trajectories"); print("="*150)
print(" W(clf) is the floor for the classifier alone; W(FULL) for the classifier plus the six rules.")
print(f" {'Category':42} {'clf':>7} {'F':>5} {'recon':>6} {'destr':>6} {'hijack':>6} {'persist':>7} {'anom':>5} {'FULL':>6} {'W(clf)':>10} {'W(FULL)':>10}")
print("-"*150)
def pc(x): return f"{100*x[0]/x[1]:.0f}%({x[1]})" if x[1] else "-"
for catg in ORDER:
    if catg not in cat: continue
    c=cat[catg]
    ck,cn=c['clasif'][0],c['clasif'][1]; fk,fn=c['FULL'][0],c['FULL'][1]
    wc=f"{100*wilson_lb(ck,cn):.0f}%(N{cn})" if cn else "-"; wf=f"{100*wilson_lb(fk,fn):.0f}%(N{fn})" if fn else "-"
    print(f" {catg:42} {pc(c['clasif']):>7} {pc(c['F']):>5} {pc(c['recon']):>6} {pc(c['destruct']):>6} {pc(c['hijack']):>6} {pc(c['persist']):>7} {pc(c['anom']):>5} {pc(c['FULL']):>6} {wc:>10} {wf:>10}")
print("\nReading the table:")
print(" - N counts distinct trajectories; byte-identical repeats are collapsed.")
print(" - Attack windows identical to held-out ones are excluded from training.")
print(" - W(clf) shows the classifier alone falling to roughly 0% on the external tools.")
