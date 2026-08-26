#!/usr/bin/env python3
"""Desenează schema de DETECȚIE la runtime a unei intruziuni pe flux → PNG/PDF."""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Polygon

fig, ax = plt.subplots(figsize=(11.5, 12.6))
ax.set_xlim(0, 12)
ax.set_ylim(0, 13.2)
ax.axis("off")

GRAY_F, GRAY_E = "#eef1f4", "#5b6670"
TEAL_F, TEAL_E = "#d7efea", "#1f8a78"      # XGBoost
ORNG_F, ORNG_E = "#fce8d2", "#d9822b"      # Autoencoder
VIOL_F, VIOL_E = "#e9e1f4", "#6f4fa3"      # fuziune
AMBR_F, AMBR_E = "#fdf3d0", "#b9962a"      # decizie
RED_F,  RED_E  = "#fbdede", "#c0392b"      # alertă
GRN_F,  GRN_E  = "#dcefda", "#3a8a3a"      # benign


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
                fontsize=title_fs, zorder=3, color="#222", fontweight="bold")


def diamond(cx, cy, hw, hh, fc, ec, text, fs=12):
    pts = [(cx, cy + hh), (cx + hw, cy), (cx, cy - hh), (cx - hw, cy)]
    ax.add_patch(Polygon(pts, closed=True, facecolor=fc, edgecolor=ec,
                         linewidth=2.0, zorder=2))
    ax.text(cx, cy, text, ha="center", va="center", fontsize=fs,
            fontweight="bold", color="#222", zorder=3)


def arrow(x1, y1, x2, y2, color="#5b6670", label="", lx=0.0, ly=0.0, lcolor=None):
    ax.add_patch(FancyArrowPatch(
        (x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=17,
        linewidth=2.0, color=color, shrinkA=1, shrinkB=1, zorder=1))
    if label:
        ax.text((x1 + x2) / 2 + lx, (y1 + y2) / 2 + ly, label,
                fontsize=11, fontweight="bold", color=lcolor or color, zorder=4,
                bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none"))


ax.text(6, 12.9, "Detecția unei intruziuni pe flux (runtime)",
        ha="center", va="center", fontsize=15, fontweight="bold", color="#1a1a1a")

# ---- noduri ----
box(6, 11.95, 8.6, 0.95, GRAY_F, GRAY_E, title="Trafic în clusterul Kubernetes",
    body="flux benign  —  sau  —  atac (scanare · DDoS · exploit CVE · exfiltrare)")

box(6, 10.5, 9.2, 1.0, GRAY_F, GRAY_E, title="Captură & agregare în flow record",
    body="pachete pe interfața CNI (ex. ovn0)\n→ NTLFlowLyzer / CICFlowMeter → vector de features")

box(6, 9.05, 9.2, 0.95, GRAY_F, GRAY_E, title="Preprocesare",
    body="drop identificatori · binarizare · protocol→IANA · curățare  (AE: + StandardScaler)")

box(3, 7.05, 4.7, 2.0, TEAL_F, TEAL_E, title="XGBoost  (supervised)",
    body="« seamănă cu un\natac cunoscut? »\n\n→ probabilitate p_xgb")

box(9, 7.05, 4.7, 2.0, ORNG_F, ORNG_E, title="Autoencoder  (unsupervised)",
    body="« deviază de la\ntraficul normal? »\n\n→ scor p_ae (din MSE)")

box(6, 5.05, 7.0, 0.95, VIOL_F, VIOL_E, title="Fuziune (Platt)",
    body="score = 0,7 · p_xgb  +  0,3 · p_ae")

diamond(6, 3.25, 1.95, 0.95, AMBR_F, AMBR_E, "score > prag ?")

box(2.7, 1.25, 4.3, 1.05, RED_F, RED_E, title="ALERTĂ — INTRUZIUNE",
    body="→ Alert Correlator / SOC", title_fs=11.5)

box(9.3, 1.25, 4.3, 1.05, GRN_F, GRN_E, title="TRAFIC NORMAL",
    body="permis, fără alertă", title_fs=11.5)

# ---- săgeți ----
arrow(6, 11.475, 6, 11.02)                        # attacker → capture
arrow(6, 10.0, 6, 9.55)                           # capture → preprocess
arrow(4.5, 8.575, 3.3, 8.08, color=TEAL_E)        # preprocess → xgb
arrow(7.5, 8.575, 8.7, 8.08, color=ORNG_E)        # preprocess → ae
arrow(3.3, 6.05, 5.0, 5.56, color=TEAL_E, label="p_xgb", lx=-0.55, ly=0.05)
arrow(8.7, 6.05, 7.0, 5.56, color=ORNG_E, label="p_ae", lx=0.55, ly=0.05)
arrow(6, 4.575, 6, 4.24, color=VIOL_E)            # fusion → decizie
arrow(4.05, 3.25, 2.9, 1.80, color=RED_E, label="DA", lx=-0.4, ly=0.15, lcolor=RED_E)
arrow(7.95, 3.25, 9.1, 1.80, color=GRN_E, label="NU", lx=0.4, ly=0.15, lcolor=GRN_E)

out_dir = os.path.join(os.path.dirname(__file__), "images")
os.makedirs(out_dir, exist_ok=True)
png = os.path.join(out_dir, "flow_detection.png")
pdf = os.path.join(out_dir, "flow_detection.pdf")
plt.savefig(png, dpi=200, bbox_inches="tight", facecolor="white")
plt.savefig(pdf, bbox_inches="tight", facecolor="white")
print("Saved:", png)
print("Saved:", pdf)
