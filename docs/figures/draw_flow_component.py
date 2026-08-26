#!/usr/bin/env python3
"""Desenează schema Componentei Flow (XGBoost + Autoencoder) → PNG/PDF pentru raport."""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

fig, ax = plt.subplots(figsize=(11.5, 11.8))
ax.set_xlim(0, 12)
ax.set_ylim(0, 12.8)
ax.axis("off")

# culori
GRAY_F, GRAY_E = "#eef1f4", "#5b6670"
TEAL_F, TEAL_E = "#d7efea", "#1f8a78"      # XGBoost (supervised)
ORNG_F, ORNG_E = "#fce8d2", "#d9822b"      # Autoencoder (unsupervised)
VIOL_F, VIOL_E = "#e9e1f4", "#6f4fa3"      # fuziune
RED_F,  RED_E  = "#fbdede", "#c0392b"      # alertă


def box(cx, cy, w, h, fc, ec, title="", body="", title_fs=13, body_fs=9.5):
    ax.add_patch(FancyBboxPatch(
        (cx - w / 2, cy - h / 2), w, h,
        boxstyle="round,pad=0.04,rounding_size=0.16",
        linewidth=1.9, edgecolor=ec, facecolor=fc, zorder=2))
    if body:
        ax.text(cx, cy + h / 2 - 0.28, title, ha="center", va="top",
                fontsize=title_fs, fontweight="bold", color=ec, zorder=3)
        ax.text(cx, cy + h / 2 - 0.66, body, ha="center", va="top",
                fontsize=body_fs, zorder=3, linespacing=1.45, color="#222")
    else:
        ax.text(cx, cy, title, ha="center", va="center",
                fontsize=title_fs, zorder=3, linespacing=1.45,
                color="#222", fontweight="bold")


def arrow(x1, y1, x2, y2, color="#5b6670", label="", lx=0.0, ly=0.0):
    ax.add_patch(FancyArrowPatch(
        (x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=17,
        linewidth=2.0, color=color, shrinkA=1, shrinkB=1, zorder=1))
    if label:
        ax.text((x1 + x2) / 2 + lx, (y1 + y2) / 2 + ly, label,
                fontsize=11, style="italic", fontweight="bold",
                color=color, zorder=4,
                bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none"))


# ---- titlu ----
ax.text(6, 12.45, "Componenta Flow — detector hibrid XGBoost + Autoencoder",
        ha="center", va="center", fontsize=15, fontweight="bold", color="#1a1a1a")

# ---- noduri ----
box(6, 11.2, 7.2, 0.95, GRAY_F, GRAY_E, title="Flux de rețea (flow record)",
    body="pcap  →  NTLFlowLyzer (BCCC) / CICFlowMeter (ITU)")

box(6, 9.75, 9.4, 1.45, GRAY_F, GRAY_E,
    title="Preprocesare  ·  load_tabular (identic pe ambele seturi)",
    body="drop identificatori (IP, port, timestamp)  ·  binarizare (benign 0 / atac 1)\n"
         "encode protocol → IANA  ·  curățare ±inf / NaN → 0  ·  (AE: + StandardScaler)")

box(3, 7.0, 4.7, 2.7, TEAL_F, TEAL_E, title="XGBoost  (supervised)",
    body="antrenat CU etichete\n500 arbori · max_depth 8\nscale_pos_weight (imbalans)\n\n"
         "« prinde DDoS cunoscut »")

box(9, 7.0, 4.7, 2.7, ORNG_F, ORNG_E, title="Autoencoder  (unsupervised)",
    body="antrenat DOAR pe benign\nMLP undercomplete\n317→128→32→8→32→128→317\n"
         "MSE de reconstrucție\n\n« prinde devieri de la normal »")

box(3, 4.55, 4.0, 0.8, TEAL_F, TEAL_E, title="Platt calibration", title_fs=11)
box(9, 4.55, 4.0, 0.8, ORNG_F, ORNG_E, title="Platt calibration", title_fs=11)

box(6, 2.7, 7.4, 1.05, VIOL_F, VIOL_E, title="Fuziune",
    body="score = 0,7 · p_xgb  +  0,3 · p_ae        (weighted_70_30)")

box(6, 1.05, 5.0, 0.85, RED_F, RED_E, title="Alertă  dacă  score > prag", title_fs=12)

# ---- săgeți ----
arrow(6, 10.725, 6, 10.48)                       # input → prep
arrow(4.4, 9.025, 3.2, 8.36, color=TEAL_E)       # prep → xgb
arrow(7.6, 9.025, 8.8, 8.36, color=ORNG_E)       # prep → ae
arrow(3, 5.65, 3, 4.96, color=TEAL_E)            # xgb → platt
arrow(9, 5.65, 9, 4.96, color=ORNG_E)            # ae → platt
arrow(3.3, 4.15, 5.0, 3.27, color=TEAL_E, label="p_xgb", lx=-0.55, ly=0.05)   # platt → fuse
arrow(8.7, 4.15, 7.0, 3.27, color=ORNG_E, label="p_ae", lx=0.55, ly=0.05)     # platt → fuse
arrow(6, 2.175, 6, 1.49, color=VIOL_E)           # fuse → alert

out_dir = os.path.join(os.path.dirname(__file__), "images")
os.makedirs(out_dir, exist_ok=True)
png = os.path.join(out_dir, "flow_component.png")
pdf = os.path.join(out_dir, "flow_component.pdf")
plt.savefig(png, dpi=200, bbox_inches="tight", facecolor="white")
plt.savefig(pdf, bbox_inches="tight", facecolor="white")
print("Saved:", png)
print("Saved:", pdf)
