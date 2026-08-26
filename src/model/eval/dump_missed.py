#!/usr/bin/env python3
"""Dump raw event composition for the 7 missed episodes and a few detected ones."""
import json, subprocess
from collections import Counter
CID = open("/tmp/ids_law_cid.txt").read().strip()

SESS = {
 "17":("2026-06-04T14:30:23Z","2026-06-04T14:31:43Z"),
 "20":("2026-06-04T14:35:14Z","2026-06-04T14:36:53Z"),
 "21":("2026-06-04T14:37:00Z","2026-06-04T14:37:48Z"),
 "23":("2026-06-04T14:39:44Z","2026-06-04T14:40:59Z"),
 "24":("2026-06-04T14:41:05Z","2026-06-04T14:42:11Z"),
}

def q(start,end,actor):
    KQL=(f"AzureDiagnostics | where Category in ('kube-audit','kube-audit-admin') "
         f"| where TimeGenerated between (datetime({start}) .. datetime({end})) "
         f"| order by TimeGenerated asc | project log_s")
    r=subprocess.run(["az","rest","--method","post","--url",
        f"https://api.loganalytics.io/v1/workspaces/{CID}/query","--resource","https://api.loganalytics.io",
        "--headers","Content-Type=application/json","--body",json.dumps({"query":KQL})],
        capture_output=True,text=True)
    if r.returncode!=0 or not r.stdout.strip():
        print("  !! az err rc=",r.returncode,"stderr:",r.stderr[-300:]); return []
    rows=json.loads(r.stdout)["tables"][0]["rows"]
    out=[]
    for (log,) in rows:
        try: e=json.loads(log)
        except: continue
        a=((e.get("impersonatedUser") or {}).get("username")) or (e.get("user") or {}).get("username","")
        if actor not in a: continue
        o=e.get("objectRef") or {}; ann=e.get("annotations") or {}
        out.append((e.get("verb",""),o.get("resource",""),o.get("subresource",""),
            (e.get("responseStatus") or {}).get("code",0),
            ann.get("authorization.k8s.io/decision","")))
    return out

# The 7 missed: (session, actor)
missed=[("21","adversary-external"),("21","adversary-insider"),("24","adversary-insider"),
        ("21","recon-sa"),("23","recon-sa"),("20","victim-sa"),("24","victim-sa")]
print("########## 7 MISSED EPISODES ##########")
for si,a in missed:
    st,en=SESS[si]
    evs=q(st,en,a)
    vr=Counter((v,r,(d or 'allow')) for v,r,s,c,d in evs)
    nforbid=sum(1 for v,r,s,c,d in evs if d=="forbid")
    nsecrets=sum(1 for v,r,s,c,d in evs if r=="secrets")
    nexec=sum(1 for v,r,s,c,d in evs if s=="exec")
    nrbac=sum(1 for v,r,s,c,d in evs if r in {"clusterroles","clusterrolebindings","roles","rolebindings"})
    print(f"\n== s{si} {a}: {len(evs)} events | forbid={nforbid} secrets={nsecrets} exec={nexec} rbac={nrbac}")
    for (v,r,d),n in vr.most_common(8):
        print(f"     {n:>3}x {v}:{r} [{d}]")

# For contrast: detected victim-sa s17 (39 win, pmax 1.0)
print("\n########## CONTRAST: DETECTED victim-sa s17 (39 win pmax=1.0) ##########")
evs=q(*SESS["17"],"victim-sa")
vr=Counter((v,r,(d or 'allow')) for v,r,s,c,d in evs)
nsec=sum(1 for v,r,s,c,d in evs if r=="secrets"); nf=sum(1 for v,r,s,c,d in evs if d=="forbid")
print(f"  {len(evs)} events | forbid={nf} secrets={nsec}")
for (v,r,d),n in vr.most_common(8): print(f"     {n:>3}x {v}:{r} [{d}]")
