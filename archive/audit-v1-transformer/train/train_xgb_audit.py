#!/usr/bin/env python3
"""XGBoost CURAT pe dataset-ul de audit API (features comportamentale rich).
NU atinge modelul de rețea (data/models/flow-bccc/xgboost_bccc). Model nou separat.
Input: reference_dataset/ref_train.csv + ref_test.csv. Features = coloanele numerice (NU 'user').
"""
import csv, json, os
from pathlib import Path
import numpy as np
import xgboost as xgb
from sklearn.metrics import (precision_recall_fscore_support, confusion_matrix,
                             roc_auc_score, average_precision_score)

HERE = Path(__file__).parent
DS = HERE.parents[2] / "data/legacy/reference_dataset"
OUT = HERE.parents[2] / "data" / "models" / "audit_api_xgb"   # data/models/audit_api_xgb (NOU, separat)
OUT.mkdir(parents=True, exist_ok=True)

def load(p):
    rows = list(csv.reader(open(p)))
    head = rows[0]; data = rows[1:]
    feat_cols = [i for i, c in enumerate(head) if c not in ("label", "user")]
    X = np.array([[float(r[i]) for i in feat_cols] for r in data], dtype=float)
    y = np.array([int(r[0]) for r in data])
    return X, y, [head[i] for i in feat_cols]

Xtr, ytr, feats = load(DS / "ref_train.csv")
Xte, yte, _ = load(DS / "ref_test.csv")
print(f"train: {len(ytr)} ({int(ytr.sum())} atac / {int((ytr==0).sum())} benign)")
print(f"test : {len(yte)} ({int(yte.sum())} atac / {int((yte==0).sum())} benign)")
print(f"features ({len(feats)}): {feats}")

spw = max(int((ytr == 0).sum()) / max(int(ytr.sum()), 1), 1)   # dezechilibru de clasă
clf = xgb.XGBClassifier(n_estimators=200, max_depth=4, learning_rate=0.1,
                        subsample=0.9, colsample_bytree=0.9, eval_metric="logloss",
                        scale_pos_weight=spw, n_jobs=2)
clf.fit(Xtr, ytr)

prob = clf.predict_proba(Xte)[:, 1]
pred = (prob >= 0.5).astype(int)
p, r, f1, _ = precision_recall_fscore_support(yte, pred, average="binary", zero_division=0)
cm = confusion_matrix(yte, pred, labels=[0, 1])
tn, fp, fn, tp = cm.ravel()
fpr = fp / max(fp + tn, 1)
auc = roc_auc_score(yte, prob); prauc = average_precision_score(yte, prob)

print("\n" + "=" * 56)
print(" XGBoost AUDIT-API (test held-out)")
print("=" * 56)
print(f"  precision={p:.3f}  recall={r:.3f}  f1={f1:.3f}")
print(f"  FPR={fpr:.3f}  ROC-AUC={auc:.3f}  PR-AUC={prauc:.3f}")
print(f"  confusion [TN={tn} FP={fp} FN={fn} TP={tp}]")
print("\n  IMPORTANȚA features (ce contează de fapt):")
imp = sorted(zip(feats, clf.feature_importances_), key=lambda kv: -kv[1])
for name, w in imp[:10]:
    print(f"    {name:24s} {w:.3f}")

clf.save_model(str(OUT / "model.json"))
json.dump({"precision": float(p), "recall": float(r), "f1": float(f1), "fpr": float(fpr),
           "roc_auc": float(auc), "pr_auc": float(prauc), "features": feats,
           "importance": {n: float(w) for n, w in imp},
           "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}},
          open(OUT / "metrics.json", "w"), indent=2)
print(f"\n  model salvat: {OUT}/model.json  (NU am atins modelul de rețea)")
