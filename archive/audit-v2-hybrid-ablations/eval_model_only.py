#!/usr/bin/env python3
# eval_model_only — ABLATIE: evalueaza CLASIFICATORUL SINGUR (fara overlay F, fara detector recon),
# si il compara cu pipeline-ul complet, ca sa vedem CAT adauga pipeline-ul peste model.
# NU modifica train_v2.py — acelasi split tool-disjunct, acelasi clasificator (recon EXCLUS din pozitive).
import csv
from collections import defaultdict, Counter
import numpy as np, xgboost as xgb
from sklearn.metrics import roc_auc_score, average_precision_score, precision_score, f1_score
from pathlib import Path
REPO=Path(__file__).resolve().parents[3]
DS=str(REPO/"src/dataset/reference/ref_v2_all.csv")
OUT_MD=str(REPO/"docs/results/EVAL_MODEL_VS_PIPELINE.md")
OLD=["forbid_ratio","n_forbid","n_events","n_distinct_resource","n_distinct_verb","n_distinct_ns","n_secrets","n_exec","n_rbac","n_create","n_delete","n_list","n_4xx","n_selfreview","selfreview_ratio"]
NEW=["has_secret","has_exec","has_rbac_write","has_crb","has_forbid","secret_rate","rbac_rate","create_rate","secret_ns","severity","cum_secrets","cum_rbac_w","cum_exec","cum_crb"]
FEAT=OLD+NEW
ALLOW=["ci-deployer","compliance-scanner","sre-oncall","devops-pipeline","platform-engineer","security-auditor","platform-admin",
       "system:serviceaccount:cert-manager","system:serviceaccount:argocd","system:serviceaccount:monitoring",
       "system:serviceaccount:kube-system","aksService","readinessChecker","masterclient","system:node","system:apiserver","hcpService"]
R_RECON=5; K=2; THR=0.5

rows=list(csv.DictReader(open(DS)))
def is_recon(u): return "recon-sa" in u or "redteam-rakkess" in u
def is_atk(r): return r["label"]=="1"
def allowed(u): return any(a in u for a in ALLOW)
def fv(r): return [float(r[c]) for c in FEAT]
tool_sess=set(int(r["session"]) for r in rows if r["tool"] in ("stratus","rakkess"))
syn_sess=sorted(set(int(r["session"]) for r in rows if r["tool"]=="synthetic")-tool_sess)
cut=max(1,int(len(syn_sess)*0.7)); syn_tr=set(syn_sess[:cut]); syn_te=set(syn_sess[cut:])
def part(r):
    t=r["tool"]; s=int(r["session"])
    if t=="stratus": return "train"
    if t=="peirates": return "peirates_eval"
    if t=="rakkess": return "recon_eval"
    if s in tool_sess: return "train"
    return "train" if s in syn_tr else "test"

# clasificator IDENTIC cu train_v2 (recon exclus din pozitive)
Xtr,ytr=[],[]; episodes=defaultdict(list)
for r in rows:
    p=part(r); episodes[(p,r["session"],r["user"])].append(r)
    if p=="train" and not is_recon(r["user"]):
        Xtr.append(fv(r)); ytr.append(1 if is_atk(r) else 0)
Xtr=np.array(Xtr); ytr=np.array(ytr)
spw=max(1.0,(ytr==0).sum()/max(1,(ytr==1).sum()))
clf=xgb.XGBClassifier(n_estimators=200,max_depth=4,learning_rate=0.1,scale_pos_weight=spw,eval_metric="logloss")
clf.fit(Xtr,ytr)
def proba(rs): return clf.predict_proba(np.array([fv(r) for r in rs]))[:,1] if rs else np.array([])

# categorisire fereastra
def win_cat(r):
    p=part(r); u=r["user"]; atk=is_atk(r); rec=is_recon(u)
    if p=="train": return None
    if p=="peirates_eval": return "ESCALADARE held-out (Peirates)"
    if p=="recon_eval": return "RECON extern (rakkess)"
    if rec and atk: return "RECON sintetic (recon-sa)"
    if atk: return "ESCALADARE (atac)"
    if "ci-deployer" in u or "compliance" in u: return "BENIGN can-i"
    return "BENIGN normal"

# WINDOW-LEVEL: MODELUL SINGUR
eval_rows=[r for r in rows if part(r)!="train"]
P=proba(eval_rows)
cats=[win_cat(r) for r in eval_rows]
# buckete
ESC={"ESCALADARE (atac)","ESCALADARE held-out (Peirates)"}
RECON={"RECON sintetic (recon-sa)","RECON extern (rakkess)"}
BEN={"BENIGN can-i","BENIGN normal"}
def rate(mask):
    idx=[i for i,c in enumerate(cats) if c in mask]
    if not idx: return None
    fired=sum(1 for i in idx if P[i]>=THR); return fired,len(idx),100*fired/len(idx)
# AUC pe taskul antrenat: escaladare(+) vs benign(-)
y_auc=[]; p_auc=[]
for i,c in enumerate(cats):
    if c in ESC: y_auc.append(1); p_auc.append(P[i])
    elif c in BEN: y_auc.append(0); p_auc.append(P[i])
roc=roc_auc_score(y_auc,p_auc) if len(set(y_auc))>1 else float("nan")
pra=average_precision_score(y_auc,p_auc) if len(set(y_auc))>1 else float("nan")
yhat=[1 if p>=THR else 0 for p in p_auc]
prec=precision_score(y_auc,yhat,zero_division=0); f1=f1_score(y_auc,yhat,zero_division=0)

# per-categorie window-level
percat_w={}
for catg in ["ESCALADARE (atac)","ESCALADARE held-out (Peirates)","RECON sintetic (recon-sa)",
            "RECON extern (rakkess)","BENIGN can-i","BENIGN normal"]:
    idx=[i for i,c in enumerate(cats) if c==catg]
    if idx: percat_w[catg]=(sum(1 for i in idx if P[i]>=THR),len(idx))

# EPISODE-LEVEL: model singur vs componente vs full
def ep_class(rs,k=K): return int((proba(rs)>=THR).sum())>=k
def ep_F(rs): return any((float(r["has_crb"])>=1 or float(r["has_exec"])>=1 or (float(r["has_secret"])>=1 and float(r["secret_ns"])>=2)) for r in rs)
def ep_recon(rs,u):
    if allowed(u): return False
    return any(float(r["n_selfreview"])>=R_RECON for r in rs)
RULES=["model K=1","model K=2","+F","+recon-det","FULL hibrid"]
cat_ep=defaultdict(lambda: defaultdict(lambda:[0,0]))
for (p,s,u),rs in episodes.items():
    if p=="train": continue
    catg=win_cat(rs[0])
    m1=ep_class(rs,1); m2=ep_class(rs,2); f=ep_F(rs); rc=ep_recon(rs,u)
    vals={"model K=1":m1,"model K=2":m2,"+F":(m2 or f),"+recon-det":(m2 or rc),"FULL hibrid":(m2 or f or rc)}
    for rule,v in vals.items():
        cat_ep[catg][rule][1]+=1; cat_ep[catg][rule][0]+=int(v)

# PRINT + MD
def pc(x): return f"{100*x[0]/x[1]:.0f}% ({x[0]}/{x[1]})" if x and x[1] else "-"
ORDER=["ESCALADARE (atac)","ESCALADARE held-out (Peirates)","RECON sintetic (recon-sa)",
       "RECON extern (rakkess)","BENIGN can-i","BENIGN normal"]
L=[]
def pr(s=""): print(s); L.append(s)

pr("# Ablatie: MODEL SINGUR vs PIPELINE COMPLET (v1.2)\n")
pr(f"Clasificator XGBoost, {len(Xtr)} ferestre train (recon exclus din pozitive). Prag={THR}. Split tool-disjunct.\n")
imp=sorted(zip(FEAT,clf.feature_importances_),key=lambda x:-x[1])[:6]
pr("Importanta trasaturi: "+", ".join(f"{k} {v:.2f}" for k,v in imp)+"\n")

pr("## 1. MODEL SINGUR — nivel FEREASTRA (window-level)\n")
pr("**Taskul antrenat (escaladare vs benign):**")
pr(f"- ROC-AUC: **{roc:.3f}** | PR-AUC: **{pra:.3f}** | precision: {prec:.3f} | F1: {f1:.3f}")
e=rate(ESC); b=rate(BEN); rc=rate(RECON)
pr(f"- Recall ESCALADARE (sintetic+Peirates): **{e[2]:.1f}%** ({e[0]}/{e[1]})")
pr(f"- FPR BENIGN (fals-pozitiv): **{b[2]:.1f}%** ({b[0]}/{b[1]})")
pr(f"- Recall RECON (incidental — NU e taskul lui): {rc[2]:.1f}% ({rc[0]}/{rc[1]})\n")
pr("Per categorie (fired/total ferestre):\n")
pr("| Categorie | model singur (recall/FPR fereastra) |")
pr("|---|---|")
for c in ORDER:
    if c in percat_w: pr(f"| {c} | {pc(percat_w[c])} |")
pr("")

pr("## 2. EPISOD — model singur vs adaugarea fiecarei componente\n")
pr("| Categorie | model K=1 | model K=2 | +F | +recon-det | FULL hibrid |")
pr("|---|:--:|:--:|:--:|:--:|:--:|")
for c in ORDER:
    if c not in cat_ep: continue
    d=cat_ep[c]
    pr(f"| {c} | {pc(d['model K=1'])} | {pc(d['model K=2'])} | {pc(d['+F'])} | {pc(d['+recon-det'])} | {pc(d['FULL hibrid'])} |")
pr("")

pr("## 3. CAT ADAUGA PIPELINE-UL (delta model singur -> full)\n")
pr("| Categorie | MODEL singur (K=2) | FULL hibrid | castig |")
pr("|---|:--:|:--:|:--:|")
for c in ORDER:
    if c not in cat_ep: continue
    m=cat_ep[c]["model K=2"]; f=cat_ep[c]["FULL hibrid"]
    mp=100*m[0]/m[1] if m[1] else 0; fp=100*f[0]/f[1] if f[1] else 0
    pr(f"| {c} | {pc(m)} | {pc(f)} | {fp-mp:+.0f} pp |")
pr("")

# §4: caveat-uri VERIFICATE adversarial (4 auditori, workflow verify-model-ablation)
pr("## 4. Verificare adversariala + caveat-uri ONESTE (de pus in lucrare)\n")
pr("> 4 auditori independenti (split/leakage, metrici, artefact n_list, interpretare) au reprodus cifrele")
pr("> independent. Verdict: cifre CORECTE, split CURAT (0 suprapunere traineval, recon exclus corect).")
pr("> Dar urmatoarele NUANTE sunt obligatorii — altfel raportul induce in eroare:\n")
pr("1. **rakkess 86% NU e recall de recon, ci ARTEFACT `n_list`** (CONFIRMAT): scotand `n_list`, rakkess cade")
pr("   **85.9%  0.0%** (83260/9697) iar escaladarea ramane ~100% (Peirates 100%, sintetic 99.4%). Determinist")
pr("   pe 7 seed-uri. Modelul NU intelege recon; prinde rakkess incidental prin volumul mare de list/get.")
pr("2. **ROC-AUC / PR-AUC \"1.000\" sunt ROTUNJIRI** ale 0.999996 / 0.999879 — exista un tie real la scor 0.8874")
pr("   (4 ferestre benigne + 1 pozitiva au acelasi scor). Separabilitatea NU e literalmente perfecta.")
pr("3. **Metrici sintetice umflate de redundanta**: 88% (138/157) din ferestrele de escaladare din test sunt")
pr("   **byte-identice** cu pozitive din train (generatorul sintetic: 753 pozitive  doar 257 vectori distincti).")
pr("   Nu e leakage (split curat), dar ferestre escaladare **genuin-noi ≈ 19**, nu 157. Generalizarea reala pe")
pr("   atac se sprijina pe **~19 sintetice noi + 23 Peirates + 21 Stratus** = esantion mic.")
pr("4. **Escaladarea sintetica de test NU e attacker-disjuncta** (aceiasi actori victim-sa/adversary-* in train")
pr("   si test; doar sesiunea difera)  acelasi optimism sintetic criticat in v1.1.")
pr("5. **\"F redundant pe escaladare\" e SUBESTIMARE, nu refutare**: held-out-ul (Peirates) e mai DENS decat")
pr("   trainul (n_secrets 6.22 vs 2.63), iar regimul DILUAT care a spart clasificatorul in v1.1 (Stratus,")
pr("   window-recall 4.1%) e acum **in TRAIN**, nu in held-out  100% pe el e *fitted*, nu generalizare. F ramane")
pr("   justificat pentru atac rar/low-tempo/single-shot; testul nu contine acel regim.")
pr("6. **N la nivel de EPISOD e 1–4** pe categoriile cheie (escaladare 3+1, recon-sa 1, benign can-i 4)  toate")
pr("   delta-urile din §3 sunt **ILUSTRATIVE, nu statistice**.")
pr("7. **recon-sa +100pp** vine din regula **allowlist+rata** (`n_selfreview≥5`), NU din ML, pe N=1 episod; recon-sa")
pr("   e fundamental ambiguu cu `can-i` benign.")
pr("8. Cei 4 FP benigni sunt practic **acelasi tipar** (`n_list=1`, sre-oncall+system:node) repetat  FPR 0.2%")
pr("   reflecta 1 pattern, nu 4 erori independente; benignul de test vine din aceleasi sesiuni ca trainul.")
pr("")
pr("**CONCLUZIE ONESTA (cat ajuta pipeline-ul):** pe **escaladare densa** modelul singur e suficient (pipeline +0pp,")
pr("ba F costa +4pp FP); pe **recon-sa** pipeline-ul adauga totul (+100pp, dar prin REGULA, nu ML); **rakkess** e")
pr("prins de model doar ca artefact n_list. Valoarea lui **F** (robustete la diluare) NU e testata aici, deci nici")
pr("dovedita nici infirmata. Net: **modelul e calul de bataie pe escaladare; detectorul de recon e esential pt recon;**")
pr("**overlay-ul F ramane o asigurare pt atac diluat, nedemonstrata de acest set.**")
open(OUT_MD,"w").write("\n".join(L))
print(f"\n>> scris {OUT_MD}")
