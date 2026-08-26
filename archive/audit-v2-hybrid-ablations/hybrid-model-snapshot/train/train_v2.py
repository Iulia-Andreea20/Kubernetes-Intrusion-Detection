#!/usr/bin/env python3
# train_v2 — pipeline HIBRID v1.5 ML-CENTRIC (focus: ML prinde cat mai multe atacuri).
# Clasificator XGBoost (A_minus_nlist) antrenat pe ESCALADARE + LATERAL + IMPACT + EVASION; recon EXCLUS (ambiguu).
# Held-out: unelte externe reale (Stratus rar, Peirates dens) + diluat (lowslow) pt escaladare [TOOL-disjunct];
#           lateral/impact/evasion split PE IDENTITATE (train unele identitati, held-out altele) [IDENTITY-disjunct].
# Reguli: recon = allowlist+rata can-i; destruct = allowlist+rata stergeri (BACKUP defense-in-depth peste ML).
import csv
from collections import defaultdict, Counter
import numpy as np, xgboost as xgb
DS="/Users/iulia-andreeagrigore/Projects/Kubernetes-Intrusion-Detection/src/dataset/reference/ref_v2_all.csv"
OLD=["forbid_ratio","n_forbid","n_events","n_distinct_resource","n_distinct_verb","n_distinct_ns","n_secrets","n_exec","n_rbac","n_create","n_delete","n_list","n_4xx","n_selfreview","selfreview_ratio"]
NEW=["has_secret","has_exec","has_rbac_write","has_crb","has_forbid","secret_rate","rbac_rate","create_rate","secret_ns","severity","cum_secrets","cum_rbac_w","cum_exec","cum_crb","has_impersonation","n_distinct_impersonated","n_create_workload","has_csr","has_tokenreq"]
# n_create_workload (regula hijack), has_csr/has_tokenreq (regula persist) sunt DOAR pt reguli de suport, NU pt clasificator.
FEAT=[c for c in OLD+NEW if c not in ("n_list","n_create_workload","has_csr","has_tokenreq")]   # A_minus_nlist
# Allowlist ANCORAT (exact + prefix de namespace) — NU substring. Repara bypass-ul: un atacator in `default`
# (system:serviceaccount:default:adversary-*) sau cu nume continand un token allowlistat NU mai e exonerat.
ALLOW_EXACT={"ci-deployer","sre-oncall","devops-pipeline","platform-engineer","security-auditor","platform-admin",
       "aksService","readinessChecker","masterclient","hcpService","system:apiserver",
       "system:serviceaccount:default:compliance-scanner-sa"}   # SA benign EXACT in default (NU tot default-ul)
ALLOW_PREFIX=("system:serviceaccount:kube-system:","system:serviceaccount:monitoring:",
       "system:serviceaccount:cert-manager:","system:serviceaccount:argocd:","system:node:",
       "system:serviceaccount:falco:")   # falco = componenta runtime a IDS-ului (de încredere; FP clasif live)
R_RECON=5; D_DEL=5; H_WL=1; K=2   # H_WL: prag creari workload pt regula hijack (workload-hijack/miner)
# split PE IDENTITATE pt clasele fara unealta externa (train ~half, held-out restul)
LAT_TR={"adversary-lateral","adversary-lat-1","adversary-lat-2"}; LAT_HO={"adversary-lateral2","adversary-lat-3","adversary-lat-8","adversary-lat-9","adversary-lat-10"}
# IMPACT regenerat cu variatie comportamentala (vechiul templat adversary-impact/imp-1/2/3 scos). Split PE COMPORTAMENT:
IMP_TR={"adversary-impv-1","adversary-impv-2","adversary-impv-3"}  # burst-1tip / multi-tip / miner
IMP_HO={"adversary-impv-4","adversary-impv-5","adversary-impv-6","adversary-impv-11","adversary-impv-12","adversary-impv-13"}  # +episoade Wilson LB
# ESCALADARE + EVASION regenerate cu variatie (vechiul templat scos). Split PE COMPORTAMENT (held-out diferit):
ESCV_TR={"adversary-escv-1","adversary-escv-2","adversary-escv-3"} # forbid-trail / multi-ns-dump / rbac-create
ESCV_HO={"adversary-escv-4","adversary-escv-5","adversary-escv-6"} # exec-focus / single-ns-hoard / slow-mixt
EVA_TR={"adversary-evav-1","adversary-evav-2","adversary-evav-3"}  # npevt / whcrb / rbevt
EVA_HO={"adversary-evav-4","adversary-evav-5","adversary-evav-6","adversary-evav-11","adversary-evav-12","adversary-evav-13"}  # +episoade Wilson LB

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
    if t=="stratus":  return "stratus_eval"       # HELD-OUT extern (rar)
    if t=="peirates": return "peirates_eval"      # HELD-OUT extern (dens)
    if t=="lowslow":  return "lowslow_eval"        # HELD-OUT (diluat)
    if t=="lateral":  return "train" if u in LAT_TR else "lateral_eval"
    if t=="impact":   return "train" if u in IMP_TR else ("impact_eval" if "impv" in u else "drop")  # impv-* nou -> eval; vechi templat (imp-N/impact) -> drop
    if t=="escv":     return "train" if u in ESCV_TR else "escv_eval"     # escaladare regenerata variata
    if t=="evasion":  return "train" if u in EVA_TR else ("evasion_eval" if "evav" in u else "drop")  # evav-* nou -> eval; vechi -> drop
    if t=="persistence": return "persistence_eval"   # HELD-OUT extern (Stratus) — tactica NOUA, tool-disjunct
    if t=="lateralext":  return "lateralext_eval"     # HELD-OUT extern (Stratus token-reuse) — lateral tool-disjunct
    if t=="compromised": return "compromised_eval"    # HELD-OUT: identitate kube-system COMPROMISA (allowlistata) — gaura granitei de incredere
    if is_recon(u):   return "recon_eval" if s in (5,6) else "train_recon_excl"
    if s in (1,2,3,4): return "train"
    if s in (5,6):     return "test"
    return "train"

# Fix #2 (audit ML runda 6): split FEATURE-disjunct la nivel de TRAIECTORIE INAINTE de train.
# Exclude din train ORICE fereastra de atac byte-identica cu o fereastra de EVAL (held-out) => train ∩ eval = ∅
# la nivel de fereastra. Repara leakage-ul la sursa (nu doar mascat la evaluare). DOAR in pipeline-ul de EVALUARE
# (train_production antreneaza pe TOT, by design).
EVALPARTS={"stratus_eval","peirates_eval","lowslow_eval","lateral_eval","impact_eval","evasion_eval",
           "recon_eval","persistence_eval","lateralext_eval","escv_eval"}
EVALVECS={vec(r) for r in rows if part(r) in EVALPARTS and is_atk(r)}
# Fix #4 (audit SECURITATE runda 5/6): allowlist-ul prin PREFIX (kube-system etc.) NU mai exonereaza orbeste.
# KNOWN = identitatile allowlistate OBSERVATE in benign (controllerele reale). O identitate allowlistata-prin-prefix
# care NU e in KNOWN (ex. SA fabricat de atacator in kube-system) NU mai e exonerata de regulile de rata.
# (Analiza empirica a aratat ca o regula de RATA pura nu merge: controllerele benigne fac mass-delete/token la rate >= atac;
#  semnalul discriminant e ca identitatea e NECUNOSCUTA, nu rata.) Reziduu onest: un controller EXISTENT compromis (token furat)
#  ramane in KNOWN -> ar cere profil comportamental per-identitate (lucru viitor).
KNOWN_ALLOW={r["user"] for r in rows if r["label"]=="0" and allowed(r["user"])}
# CLASIFICATOR (escaladare+lateral+impact+evasion; recon exclus; DEDUPED + FEATURE-disjunct de eval)
seen=set(); Xtr,ytr=[],[]; episodes=defaultdict(list); n_leak=0
for r in rows:
    p=part(r); episodes[(p,r["session"],uid(r))].append(r)
    if p=="train" and not is_recon(uid(r)):
        # IMPACT = stergere masiva (T1485). Excludem ferestrele de workload-hijack/miner (create) din pozitive:
        # diagnostic FP a aratat ca semnalul de CREARE al minerului producea fals-pozitive pe crearile benigne
        # de noduri AKS (FP 2/57 -> 0/57, held-out neschimbat). Vezi eval_fp_diagnostic.py.
        if r["tool"]=="impact" and is_atk(r) and not (float(r["n_delete"])>=1 and float(r["n_create"])==0): continue
        if is_atk(r) and vec(r) in EVALVECS: n_leak+=1; continue   # FEATURE-disjunct: nu antrena pe ferestre din eval
        key=(vec(r),r["label"])
        if key in seen: continue
        seen.add(key); Xtr.append(fv(r)); ytr.append(1 if is_atk(r) else 0)
import os
Xtr=np.array(Xtr); ytr=np.array(ytr); spw=max(1.0,(ytr==0).sum()/max(1,(ytr==1).sum()))
# CAP spw: agresivitatea modelului NU trebuie sa depinda de cat benign incidental s-a colectat
# (sesiunile de atac aduc benign de control-plane care umfla spw 10.75->13.27 -> FP pe infra benigna 7%->39%).
# Cap=11 = punctul de operare validat in v2.0 (spw original ~10.75). Restaureaza FP benign 4%, recall held-out neschimbat.
SPW_CAP=float(os.environ.get("SPW_CAP","11"))
if SPW_CAP>0: spw=min(spw,SPW_CAP)
clf=xgb.XGBClassifier(n_estimators=200,max_depth=4,learning_rate=0.1,scale_pos_weight=spw,eval_metric="logloss",random_state=0).fit(Xtr,ytr)
def proba(rs): return clf.predict_proba(np.array([fv(r) for r in rs]))[:,1] if rs else np.array([])

# detectoare pe EPISOD
def ep_class(rs): return int((proba(rs)>=0.5).sum())>=K
def ep_F(rs,u):   # ALLOWLIST-GATED (validat live): control-plane managed face CRB-create/secret-multi-ns BENIGN
    if allowed(u): return False    # (masterclient creează CRB, cainjector watch secrets multi-ns) -> pe allowlistat doar `anom`
    return any((float(r["has_crb"])>=1 or float(r["has_exec"])>=1 or float(r["has_impersonation"])>=1 or (float(r["has_secret"])>=1 and float(r["secret_ns"])>=2)) for r in rs)
def ep_recon(rs,u):
    if allowed(u): return False
    return any(float(r["n_selfreview"])>=R_RECON for r in rs)
def ep_destruct(rs,u):
    if allowed(u): return False
    return any(float(r["n_delete"])>=D_DEL for r in rs)
def ep_hijack(rs,u):   # SUPORT: workload-hijack/miner (cazul scos din ML ca sa scada FP) -> regula dedicata
    if allowed(u): return False
    return any(float(r["n_create_workload"])>=H_WL for r in rs)
def ep_persist(rs,u):  # SUPORT: persistence via CSR self-approve / TokenRequest abuse (module Stratus ratate de ML+F)
    if allowed(u): return False  # cert-manager/csr-controller/kubelet sunt allowlistate -> NU declanseaza
    return any(float(r["has_csr"])>=1 or float(r["has_tokenreq"])>=1 for r in rs)
def ep_anom(rs,u):  # SUPORT: SA FABRICAT intr-un ns allowlistat (ex. system:serviceaccount:kube-system:evil) -> aplica regulile de rata
    if not allowed(u): return False        # ne-allowlistat: deja acoperit de recon/destruct/hijack/persist
    if not u.startswith("system:serviceaccount:"): return False  # DOAR SA-uri; NU kubelet (system:node:, nume per-cluster) / infra managed
    if u in KNOWN_ALLOW: return False       # SA benign cunoscut -> exonerat (reziduu: controller existent compromis)
    return any(float(r["n_delete"])>=D_DEL or float(r["n_selfreview"])>=R_RECON or float(r["n_create_workload"])>=H_WL
               or float(r["has_csr"])>=1 or float(r["has_tokenreq"])>=1 for r in rs)

def catg_of(p,u,atk):
    M={"stratus_eval":"HELD-extern escaladare RARA (Stratus)","peirates_eval":"HELD-extern escaladare DENSA (Peirates)",
       "lowslow_eval":"HELD escaladare DILUATA (lowslow)","lateral_eval":"HELD-id LATERAL (impersonare)",
       "impact_eval":"HELD-id IMPACT (stergere)","evasion_eval":"HELD-id DEFENSE EVASION","recon_eval":"HELD recon (rakkess)",
       "persistence_eval":"HELD-EXTERN PERSISTENCE (Stratus)","lateralext_eval":"HELD-EXTERN LATERAL token (Stratus)",
       "escv_eval":"HELD-id ESCALADARE variat (sint)","compromised_eval":"HELD kube-system COMPROMIS (allowlistat)"}
    if p in M: return M[p]
    if p=="test": return ("IN-DIST escaladare (sintetic)" if (atk and not is_recon(u)) else "IN-DIST recon-sa" if atk else
                          ("BENIGN can-i" if ("ci-deployer" in u or "compliance" in u) else "BENIGN normal"))
    return None

# ONESTITATE STATISTICA (raspuns la auditul ML rundei 5)
# TRAINPOS = vectorii de fereastra POZITIVI vazuti la antrenare -> pt a detecta scurgerea train<->eval la nivel de fereastra
TRAINPOS={v for (v,lab) in seen if lab=="1"}
def ep_class_novel(rs):  # clasif DOAR pe ferestre NEvazute in train (feature-disjunct strict; rezolva leakage-ul la nivel fereastra)
    novel=[r for r in rs if vec(r) not in TRAINPOS]
    return ep_class(novel)
# Fix #1: dedup TRAIECTORII byte-identice per categorie INAINTE de a numara N (Wilson presupune trials INDEPENDENTE;
# Stratus refolosea acelasi modul pe sesiuni diferite -> traiectorii identice umflau N). N_distinct = traiectorii unice.
cat=defaultdict(lambda: defaultdict(lambda: [0,0]))
catsig=defaultdict(set)
for (p,s,u),rs in episodes.items():
    catg=catg_of(p,u,is_atk(rs[0]))
    if not catg: continue
    sig=tuple(vec(r) for r in rs)            # semnatura traiectoriei (secventa de vectori de fereastra)
    if sig in catsig[catg]: continue          # traiectorie byte-identica deja numarata -> NU o numar de 2 ori
    catsig[catg].add(sig)
    fullu=rs[0]["user"]   # user COMPLET pt allowlist (uid scurt nu prinde prefixele system:serviceaccount:...)
    naw=not allowed(fullu)   # clasificatorul alertează SINGUR doar pt NE-allowlistat (FP pe infra de încredere — validat live)
    m=ep_class(rs) and naw; mn=ep_class_novel(rs) and naw; f=ep_F(rs,fullu); rc=ep_recon(rs,fullu); d=ep_destruct(rs,fullu); hj=ep_hijack(rs,fullu); ps=ep_persist(rs,fullu); an=ep_anom(rs,fullu)
    full=m or f or rc or d or hj or ps or an; full_nov=mn or f or rc or d or hj or ps or an
    for rule,fn in [("clasif",m),("clasif_nov",mn),("F",f),("recon",rc),("destruct",d),("hijack",hj),("persist",ps),("anom",an),("FULL",full),("FULL_nov",full_nov)]:
        cat[catg][rule][1]+=1; cat[catg][rule][0]+=int(fn)

print(f">> train DEDUPED + FEATURE-disjunct: {len(Xtr)} ferestre ({int(ytr.sum())} poz; recon exclus). FEAT={len(FEAT)}. Ferestre de atac excluse (byte-identice cu eval, anti-leakage): {n_leak}.")
print("   importanta top:", {k:round(float(v),3) for k,v in sorted(zip(FEAT,clf.feature_importances_),key=lambda x:-x[1])[:6]})
ORDER=["IN-DIST escaladare (sintetic)","HELD-id ESCALADARE variat (sint)","HELD-extern escaladare DENSA (Peirates)","HELD-extern escaladare RARA (Stratus)",
       "HELD escaladare DILUATA (lowslow)","HELD-id LATERAL (impersonare)","HELD-id IMPACT (stergere)","HELD-id DEFENSE EVASION",
       "HELD-EXTERN PERSISTENCE (Stratus)","HELD-EXTERN LATERAL token (Stratus)","HELD kube-system COMPROMIS (allowlistat)","IN-DIST recon-sa","HELD recon (rakkess)","BENIGN can-i","BENIGN normal"]
def wilson_lb(k,n,z=1.96):  # limita inferioara Wilson 95% (k succese din n)
    if n==0: return 0.0
    p=k/n; d=1+z*z/n
    return max(0.0,(p+z*z/(2*n)-z*np.sqrt(p*(1-p)/n+z*z/(4*n*n)))/d)
print("\n"+"="*150); print(" PIPELINE HIBRID v2.1-RIGUROS (pe EPISOD, N=traiectorii DISTINCTE, train FEATURE-disjunct de eval)"); print("="*150)
print(" Wilson DUBLU: W(clasif)=podeaua ML PURA (doar clasificatorul); W(FULL)=podeaua sistemului HIBRID (clasif OR 5 reguli).")
print(f" {'Categorie':42} {'clasif':>7} {'F':>5} {'recon':>6} {'destr':>6} {'hijack':>6} {'persist':>7} {'anom':>5} {'FULL':>6} {'W(clasif)':>10} {'W(FULL)':>10}")
print("-"*150)
def pc(x): return f"{100*x[0]/x[1]:.0f}%({x[1]})" if x[1] else "-"
for catg in ORDER:
    if catg not in cat: continue
    c=cat[catg]
    ck,cn=c['clasif'][0],c['clasif'][1]; fk,fn=c['FULL'][0],c['FULL'][1]
    wc=f"{100*wilson_lb(ck,cn):.0f}%(N{cn})" if cn else "-"; wf=f"{100*wilson_lb(fk,fn):.0f}%(N{fn})" if fn else "-"
    print(f" {catg:42} {pc(c['clasif']):>7} {pc(c['F']):>5} {pc(c['recon']):>6} {pc(c['destruct']):>6} {pc(c['hijack']):>6} {pc(c['persist']):>7} {pc(c['anom']):>5} {pc(c['FULL']):>6} {wc:>10} {wf:>10}")
print("\nNOTA onestitate (raspuns audit ML rundele 5-6):")
print(" - N = TRAIECTORII DISTINCTE (byte-identice colapsate; Wilson presupune trials independente).")
print(" - train FEATURE-disjunct: ferestrele de atac byte-identice cu eval sunt EXCLUSE din train (leakage reparat la SURSA).")
print(" - W(clasif) = podeaua ML PURA (arata onest ca ML singur cade ~0% pe tactici externe); W(FULL) = podeaua HIBRIDA reala.")
print("GATA train_v2 (ML-centric)")
