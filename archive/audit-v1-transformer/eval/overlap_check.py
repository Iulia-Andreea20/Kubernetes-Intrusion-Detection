#!/usr/bin/env python3
"""GATE 4.2 — verifică SUPRAPUNEREA distribuțiilor n_selfreview/ratio/burst între ferestrele BENIGN-cu-can-i
și ferestrele RECON. Dacă sunt SEPARATE curat (gap), atunci un singur prag le desparte = artefactul renăscut.
PASS = benign și recon se suprapun în banda n_selfreview 6-15 (modelul e forțat pe burst+comportament).
"""
import csv
from pathlib import Path
import numpy as np

DS = Path(__file__).resolve().parents[3] / "data/legacy/reference_dataset"
def load(p):
    rows = list(csv.reader(open(p))); head = rows[0]; data = rows[1:]
    ui = head.index("user")
    cols = {c: head.index(c) for c in ("label","n_selfreview","selfreview_ratio")}
    return head, data, ui, cols

def report(name):
    head, data, ui, cols = load(DS / name)
    nsr = np.array([float(r[cols["n_selfreview"]]) for r in data])
    ratio = np.array([float(r[cols["selfreview_ratio"]]) for r in data])
    lab = np.array([int(r[cols["label"]]) for r in data])
    users = [r[ui] for r in data]
    is_recon = np.array(["recon-sa" in u for u in users])
    is_ben_cani = (lab == 0) & (nsr >= 1)
    print(f"\n=== {name} ===")
    print(f"  ferestre: recon={int(is_recon.sum())}  benign-cu-can-i={int(is_ben_cani.sum())}")
    def stats(mask, tag):
        if not mask.any(): print(f"  {tag:18s}: (0 ferestre)"); return
        v = nsr[mask]; rt = ratio[mask]
        print(f"  {tag:18s}: n_selfreview[min={v.min():.0f} med={np.median(v):.0f} max={v.max():.0f}]  "
              f"selfreview_ratio[med={np.median(rt):.2f} max={rt.max():.2f}]")
    stats(is_recon, "RECON")
    stats(is_ben_cani, "BENIGN-can-i")
    # bandă de suprapunere 6-15
    band = (nsr >= 6) & (nsr <= 15)
    ov_recon = int((band & is_recon).sum()); ov_ben = int((band & is_ben_cani).sum())
    print(f"  banda n_selfreview∈[6,15]: recon={ov_recon} ferestre, benign-can-i={ov_ben} ferestre")
    ok = ov_recon > 0 and ov_ben > 0
    print(f"  SUPRAPUNERE în bandă: {'DA  (model forțat pe comportament: n_list/context, NU prezența can-i)' if ok else 'NU  (separare curată = risc artefact, re-acordează volumele benign)'}")

for f in ("ref_train.csv", "ref_test.csv"):
    if (DS / f).exists(): report(f)
