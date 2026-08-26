#!/usr/bin/env python3
"""CI bootstrap la nivel de EPISOD (grup = sesiune×actor), nu pe ferestre corelate.
Re-interoghează LA pentru sesiunile de TEST, rulează modelul, agregă pe episod, dă recall/FPR cu CI.
Onest: cu puține episoade independente, CI e larg (recall pe ferestre 100% e optimist)."""
import json, subprocess, random
from collections import deque, defaultdict
from pathlib import Path
import numpy as np, xgboost as xgb

HERE = Path(__file__).parent; DS = HERE.parents[2] / "data/legacy/reference_dataset"
MODEL = HERE.parents[2] / "data" / "models" / "audit_api_xgb" / "model.json"
CID = open("/tmp/ids_law_cid.txt").read().strip()
SEQ_LEN = 20; RBAC = {"clusterroles","clusterrolebindings","roles","rolebindings"}
SELF_REVIEW = {"selfsubjectaccessreviews","selfsubjectrulesreviews"}
ATTACK = {"system:serviceaccount:default:victim-sa","adversary-external","adversary-insider",
          "system:serviceaccount:default:recon-sa"}

sess = {}
for line in open(DS / "sessions.txt"):
    p = line.split()
    if len(p) >= 4 and p[0] == "SESSION": sess.setdefault(p[1], {})[p[2].lower()] = p[3][:19]
ids = sorted(sess, key=int); spans = [(i, sess[i]["start"], sess[i]["end"]) for i in ids if "start" in sess[i] and "end" in sess[i]]
cut = max(int(len(spans)*0.7), 1); test = spans[cut:]
print(f">> sesiuni TEST: {[i for i,_,_ in test]}")
def q_window(start, end):  # CHUNK pe sesiune — evită plafonul ~64MB/răspuns LA
    KQL = (f"AzureDiagnostics | where Category in ('kube-audit','kube-audit-admin') "
           f"| where TimeGenerated between (datetime({start}Z) .. datetime({end}Z)) "
           f"| project TimeGenerated, log_s | order by TimeGenerated asc")
    r = subprocess.run(["az","rest","--method","post","--url",f"https://api.loganalytics.io/v1/workspaces/{CID}/query",
        "--resource","https://api.loganalytics.io","--headers","Content-Type=application/json","--body",json.dumps({"query":KQL})],
        capture_output=True, text=True)
    if r.returncode != 0: print("!! az rest:", r.stderr[-300:]); return []
    return json.loads(r.stdout)["tables"][0]["rows"]
rows = []
for i, st, en in test: rows.extend(q_window(st, en))
def which(ts):
    t=ts[:19]
    for i,s,e in test:
        if s<=t<=e: return i
    return None
streams = defaultdict(list)
for ts, log in rows:
    try: e=json.loads(log)
    except: continue
    si=which(ts)
    if si is None: continue
    a=((e.get("impersonatedUser") or {}).get("username")) or (e.get("user") or {}).get("username","")
    o=e.get("objectRef") or {}; ann=e.get("annotations") or {}
    streams[(si,a)].append({"verb":e.get("verb",""),"resource":o.get("resource",""),"sub":o.get("subresource",""),
        "ns":o.get("namespace",""),"sourceIP":(e.get("sourceIPs") or [""])[0],
        "code":(e.get("responseStatus") or {}).get("code",0),"decision":ann.get("authorization.k8s.io/decision","")})
def feats(h):
    n=len(h); nf=sum(1 for x in h if x["decision"]=="forbid")
    nsr=sum(1 for x in h if x["verb"]=="create" and x["resource"] in SELF_REVIEW)
    run=best=0
    for x in h:
        if x["verb"]=="create" and x["resource"] in SELF_REVIEW: run+=1; best=max(best,run)
        else: run=0
    sr_ratio = round(nsr/n,3) if n>=SEQ_LEN else 0.0
    return [round(nf/n,3),nf,n,len(set(x["resource"] for x in h)),len(set(x["verb"] for x in h)),len(set(x["ns"] for x in h)),
        sum(1 for x in h if x["resource"]=="secrets"),sum(1 for x in h if x["sub"]=="exec"),sum(1 for x in h if x["resource"] in RBAC),
        sum(1 for x in h if x["verb"]=="create"),sum(1 for x in h if x["verb"]=="delete"),sum(1 for x in h if x["verb"]=="list"),
        sum(1 for x in h if isinstance(x["code"],int) and x["code"]>=400),len(set(x["sourceIP"] for x in h)),
        nsr, sr_ratio, best]
clf=xgb.XGBClassifier(); clf.load_model(str(MODEL))
# episod = (sesiune, actor); detectat = măcar o fereastră aprinde
episodes=[]  # (label, detected, n_fired, n_win)
detail=[]
nwin_tp=nwin=nwin_fp=nwin_neg=0
for (si,a),evs in streams.items():
    hist=deque(maxlen=SEQ_LEN); X=[]
    for x in evs: hist.append(x); X.append(feats(hist))
    proba=clf.predict_proba(np.array(X,dtype=float))[:,1]
    pred=(proba>=0.5).astype(int)
    lab=1 if a in ATTACK else 0
    episodes.append((lab, int(pred.sum()>0), int(pred.sum()), len(pred)))
    detail.append((si,a,lab,int(pred.sum()>0),int(pred.sum()),len(pred),float(proba.max()),float(proba.mean())))
    if lab==1: nwin_tp+=int(pred.sum()); nwin+=len(pred)
    else: nwin_fp+=int(pred.sum()); nwin_neg+=len(pred)
import json as _j
print("=== PER-EPISODE ATTACK DETAIL (actor | session | detected | n_fired/n_win | pmax | pmean) ===")
for si,a,lab,det,nf,nw,pmax,pmean in sorted(detail, key=lambda r:(r[1],int(r[0]))):
    if lab==1:
        short=a.split(":")[-1] if ":" in a else a
        print(f"  s{si:>2} {short:<20} det={det} fired={nf:>2}/{nw:<2} pmax={pmax:.3f} pmean={pmean:.3f}")
print("=== PER-ACTOR EPISODE RECALL (K=1) ===")
from collections import defaultdict as _dd
byact=_dd(lambda:[0,0]); byactK2=_dd(lambda:[0,0])
for si,a,lab,det,nf,nw,pmax,pmean in detail:
    if lab==1:
        short=a.split(":")[-1] if ":" in a else a
        byact[short][1]+=1; byact[short][0]+=det
        byactK2[short][1]+=1; byactK2[short][0]+=(1 if nf>=2 else 0)
for short in sorted(byact):
    d,t=byact[short]; d2,t2=byactK2[short]
    print(f"  {short:<20} K1 {d}/{t}={100*d/t:.0f}%   K2 {d2}/{t2}={100*d2/t2:.0f}%")
atk=[d for l,d,_,_ in episodes if l==1]; ben=[d for l,d,_,_ in episodes if l==0]
def ci(vals,n=5000):
    if not vals: return (0,0)
    out=[]
    for _ in range(n):
        s=[vals[random.randint(0,len(vals)-1)] for _ in vals]; out.append(sum(s)/len(s))
    out.sort(); return out[int(0.025*n)], out[int(0.975*n)]
random.seed(42)
print("="*60); print(" CI BOOTSTRAP LA NIVEL DE EPISOD (grup=sesiune×actor)"); print("="*60)
print(f"  episoade ATAC: {len(atk)}  |  episoade BENIGN: {len(ben)}")
rl,rh=ci(atk); fl,fh=ci(ben)
print(f"  recall pe episod : {sum(atk)}/{len(atk)} = {100*sum(atk)/max(len(atk),1):.0f}%   CI95 [{rl*100:.0f}, {rh*100:.0f}]")
print(f"  FPR pe episod    : {sum(ben)}/{len(ben)} = {100*sum(ben)/max(len(ben),1):.1f}%  CI95 [{fl*100:.1f}, {fh*100:.1f}]")
print(f"  (referință pe ferestre: recall {100*nwin_tp/max(nwin,1):.0f}%, FPR {100*nwin_fp/max(nwin_neg,1):.1f}%)")
print("  >> puține episoade independente => CI larg = imaginea ONESTĂ (100% pe ferestre e optimist).")
print("-"*60); print(" MITIGARE OPERAȚIONALĂ: flag episod doar dacă >=K ferestre se aprind")
na=sum(1 for l,_,_,_ in episodes if l==1); nb=sum(1 for l,_,_,_ in episodes if l==0)
print(f"  {'K':>3} | recall_atac        | FPR_benign")
for K in (1,2,3,5,10):
    tp=sum(1 for l,_,nf,_ in episodes if l==1 and nf>=K)
    fp=sum(1 for l,_,nf,_ in episodes if l==0 and nf>=K)
    print(f"  {K:>3} | {tp}/{na} = {100*tp/max(na,1):3.0f}%       | {fp}/{nb} = {100*fp/max(nb,1):4.1f}%")
print("  >> alege K care ține recall=100% dar taie FPR-ul operațional.")
