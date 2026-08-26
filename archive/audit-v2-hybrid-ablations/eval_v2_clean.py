#!/usr/bin/env python3
# eval_v2_clean — redesign ONEST care raspunde la cele 4 probleme gasite de verificarea adversariala:
#  (1) DEDUP pe vector de trasaturi (88% ferestre escaladare test erau byte-identice cu train) -> raportez distinct;
#  (2) Stratus MUTAT in held-out (era in train) -> generalizarea escaladarii = held-out attacker+tool-disjunct;
#  (3) compar 3 SETURI de trasaturi: A_full / A_minus_nlist / A_invariant -> decid daca scoatem n_list;
#  (4) 3 REGIMURI de densitate held-out: DENS (Peirates) / RAR (Stratus) / DILUAT (lowslow) -> masor F unde conteaza.
import csv
from collections import defaultdict, Counter
import numpy as np, xgboost as xgb
from sklearn.metrics import roc_auc_score
from pathlib import Path
REPO=Path(__file__).resolve().parents[3]
DS=str(REPO/"src/dataset/reference/ref_v2_all.csv")
OUT_MD=str(REPO/"docs/results/EVAL_REDESIGN_V2.md")
OLD=["forbid_ratio","n_forbid","n_events","n_distinct_resource","n_distinct_verb","n_distinct_ns","n_secrets","n_exec","n_rbac","n_create","n_delete","n_list","n_4xx","n_selfreview","selfreview_ratio"]
NEW=["has_secret","has_exec","has_rbac_write","has_crb","has_forbid","secret_rate","rbac_rate","create_rate","secret_ns","severity","cum_secrets","cum_rbac_w","cum_exec","cum_crb"]
ALLOW=["ci-deployer","compliance-scanner","sre-oncall","devops-pipeline","platform-engineer","security-auditor","platform-admin",
       "system:serviceaccount:cert-manager","system:serviceaccount:argocd","system:serviceaccount:monitoring",
       "system:serviceaccount:kube-system","aksService","readinessChecker","masterclient","system:node","system:apiserver","hcpService"]
K=2; THR=0.5
# seturi de trasaturi de comparat
FSETS={
 "A_full (29)": OLD+NEW,
 "A_minus_nlist (28)": [c for c in OLD+NEW if c!="n_list"],
 "A_invariant (14 noi)": NEW,                          # pur invariante la densitate
 "A_invariant+breadth (17)": NEW+["n_distinct_resource","n_distinct_verb","n_distinct_ns"],
}
rows=list(csv.DictReader(open(DS)))
def is_recon(u): return "recon-sa" in u or "redteam-rakkess" in u
def is_atk(r): return r["label"]=="1"
def allowed(u): return any(a in u for a in ALLOW)
# split: Stratus/Peirates/lowslow/rakkess = HELD-OUT; synthetic 1-4 train, 5-6 in-dist test, restul background->train
nonsyn_sess=set(int(r["session"]) for r in rows if r["tool"]!="synthetic")
syn_pure=sorted(set(int(r["session"]) for r in rows if r["tool"]=="synthetic")-nonsyn_sess)
syn_tr={1,2,3,4}; syn_te={5,6}
def part(r):
    t=r["tool"]; s=int(r["session"])
    if t=="stratus": return "stratus_eval"     # MUTAT in held-out (rar/sparse)
    if t=="peirates": return "peirates_eval"   # held-out (dens)
    if t=="lowslow": return "lowslow_eval"     # held-out (diluat, attacker-disjunct)
    if t=="rakkess": return "recon_eval"       # held-out recon
    if s in syn_tr: return "train"
    if s in syn_te: return "test"
    return "train"                             # background benign al sesiunilor de unealta -> negative train

def fv(r,F): return [float(r[c]) for c in F]
def win_cat(r):
    p=part(r); u=r["user"]; atk=is_atk(r)
    return {"stratus_eval":"HELD escaladare RARA (Stratus)","peirates_eval":"HELD escaladare DENSA (Peirates)",
            "lowslow_eval":"HELD escaladare DILUATA (lowslow)","recon_eval":"HELD recon (rakkess)"}.get(p) or (
        "IN-DIST escaladare (sintetic test)" if (p=="test" and atk and not is_recon(u)) else
        "IN-DIST recon-sa (sintetic test)" if (p=="test" and atk) else
        ("BENIGN can-i" if ("ci-deployer" in u or "compliance" in u) else "BENIGN normal") if p=="test" else None)

# DEDUP analiza (pe A_full)
def vec(r,F): return tuple(round(float(r[c]),4) for c in F)
tr_pos=[r for r in rows if part(r)=="train" and is_atk(r) and not is_recon(r["user"])]
tr_vecs=set(vec(r,OLD+NEW) for r in tr_pos)
te_esc=[r for r in rows if part(r)=="test" and is_atk(r) and not is_recon(r["user"])]
dup=sum(1 for r in te_esc if vec(r,OLD+NEW) in tr_vecs)

L=[]; pr=lambda s="":(print(s),L.append(s))
pr("# Redesign onest v2: dedup + Stratus held-out + 3 regimuri densitate × seturi de trasaturi\n")
pr(f"Train pozitive escaladare: {len(tr_pos)} ferestre -> **{len(tr_vecs)} vectori DISTINCTI** (redundanta generator sintetic).")
pr(f"In-dist test escaladare: {len(te_esc)} ferestre, din care {dup} ({100*dup/max(1,len(te_esc)):.0f}%) byte-identice cu train.\n")

REG=["IN-DIST escaladare (sintetic test)","HELD escaladare DENSA (Peirates)","HELD escaladare RARA (Stratus)",
     "HELD escaladare DILUATA (lowslow)","HELD recon (rakkess)","BENIGN normal","BENIGN can-i"]

# pt fiecare set de trasaturi: antreneaza + evalueaza window-level pe regimuri
def ep_F(rs): return any((float(r["has_crb"])>=1 or float(r["has_exec"])>=1 or (float(r["has_secret"])>=1 and float(r["secret_ns"])>=2)) for r in rs)

summary={}  # fset -> regim -> (model_win_recall, modelF_win_recall, Fonly_win)
for fname,F in FSETS.items():
    # train DEDUPED: vectori distincti (pe setul curent), negative incluse o data per vector
    seen=set(); Xtr=[]; ytr=[]
    for r in rows:
        if part(r)!="train": continue
        if is_recon(r["user"]): continue   # recon exclus din pozitive (e tratat de detector separat)
        key=(vec(r,F),r["label"])
        if key in seen: continue
        seen.add(key); Xtr.append(fv(r,F)); ytr.append(1 if is_atk(r) else 0)
    Xtr=np.array(Xtr); ytr=np.array(ytr)
    spw=max(1.0,(ytr==0).sum()/max(1,(ytr==1).sum()))
    clf=xgb.XGBClassifier(n_estimators=200,max_depth=4,learning_rate=0.1,scale_pos_weight=spw,eval_metric="logloss")
    clf.fit(Xtr,ytr)
    # window-level pe fiecare regim
    by=defaultdict(list)
    for r in rows:
        c=win_cat(r)
        if c: by[c].append(r)
    rec={}
    for c,rs in by.items():
        P=clf.predict_proba(np.array([fv(r,F) for r in rs]))[:,1]
        mfire=[p>=THR for p in P]
        Ffire=[ (float(r["has_crb"])>=1 or float(r["has_exec"])>=1 or (float(r["has_secret"])>=1 and float(r["secret_ns"])>=2)) for r in rs]
        n=len(rs)
        rec[c]=(100*sum(mfire)/n, 100*sum(a or b for a,b in zip(mfire,Ffire))/n, 100*sum(Ffire)/n, n)
    summary[fname]=rec
    # importanta n_list daca exista
    imp=dict(zip(F,clf.feature_importances_)); nlist=imp.get("n_list",0)
    pr(f"## {fname} — train {len(Xtr)} ferestre distincte ({int(ytr.sum())} poz). n_list importanta: {nlist:.3f}\n")
    pr("| Regim | model singur | model+F | doar F | n |")
    pr("|---|:--:|:--:|:--:|--:|")
    for c in REG:
        if c in rec:
            m,mf,fo,n=rec[c]
            pr(f"| {c} | {m:.0f}% | {mf:.0f}% | {fo:.0f}% | {n} |")
    pr("")

# tabel sinteza: DILUAT (testul-cheie pt F) + n_list across feature sets
pr("## SINTEZA — regimul DILUAT (low-and-slow): cat salveaza F unde modelul cedeaza\n")
pr("| Set trasaturi | model singur (diluat) | model+F (diluat) | castig F | rakkess (artefact?) |")
pr("|---|:--:|:--:|:--:|:--:|")
for fname in FSETS:
    d=summary[fname].get("HELD escaladare DILUATA (lowslow)")
    rk=summary[fname].get("HELD recon (rakkess)")
    if d:
        pr(f"| {fname} | {d[0]:.0f}% | {d[1]:.0f}% | {d[1]-d[0]:+.0f}pp | {rk[0]:.0f}% |")
pr("\n> 'rakkess (artefact?)' = recall window al MODELULUI pe rakkess. Daca scade dramatic la scoaterea n_list,")
pr("> confirma ca detectia rakkess era artefact n_list, nu recon real.")
open(OUT_MD,"w").write("\n".join(L))
print(f"\n>> scris {OUT_MD}")
