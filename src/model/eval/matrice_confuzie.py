#!/usr/bin/env python3
# Confusion matrix figure for the report, from the operational test. No title: the caption
# carries it in the document.
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# [[TP, FN], [FP, TN]]  (row = actual, column = predicted)
cm = np.array([[20, 0],
               [7, 13]])
labels = [["TP\n", "FN\n"],
          ["FP\n", "TN\n"]]
colors = [["#2e7d32", "#c62828"],
          ["#c62828", "#2e7d32"]]   # green = correct, red = error

fig, ax = plt.subplots(figsize=(6.2, 5.4))
for i in range(2):
    for j in range(2):
        ax.add_patch(plt.Rectangle((j, 1 - i), 1, 1,
                     facecolor=colors[i][j], alpha=0.30 + 0.55 * cm[i, j] / cm.max(),
                     edgecolor="#333", lw=1.5))
        ax.text(j + 0.5, 1 - i + 0.62, f"{cm[i, j]}", ha="center", va="center", fontsize=30, fontweight="bold")
        ax.text(j + 0.5, 1 - i + 0.28, labels[i][j], ha="center", va="center", fontsize=10)
ax.set_xlim(0, 2); ax.set_ylim(0, 2); ax.set_aspect("equal")
ax.set_xticks([0.5, 1.5]); ax.set_xticklabels(["Prezis: ATAC", "Prezis: BENIGN"], fontsize=11, fontweight="bold")
ax.set_yticks([1.5, 0.5]); ax.set_yticklabels(["Real: ATAC", "Real: BENIGN"], fontsize=11, fontweight="bold")
ax.xaxis.tick_top(); ax.xaxis.set_label_position("top")
for s in ax.spines.values():
    s.set_visible(False)
ax.tick_params(length=0)
plt.tight_layout()
plt.savefig("docs/results/matrice_confuzie.png", dpi=160, bbox_inches="tight")
print("saved: docs/results/matrice_confuzie.png")
