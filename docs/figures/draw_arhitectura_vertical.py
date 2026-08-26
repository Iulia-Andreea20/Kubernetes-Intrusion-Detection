#!/usr/bin/env python3
"""Generează versiunea verticală a schemei arhitecturale IDS din arhitectura_ids.drawio.

Output: arhitectura_ids_vertical.jpg (A4 portrait, 300 DPI, margini academice).
"""
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from matplotlib.lines import Line2D

OUT = Path(__file__).parent / "arhitectura_ids_vertical.jpg"

# A4 portrait: 8.27 x 11.69 inches
fig, ax = plt.subplots(figsize=(8.27, 11.69), dpi=300)
ax.set_xlim(0, 100)
ax.set_ylim(0, 140)
ax.set_aspect("equal")
ax.axis("off")

# --- Title ---
ax.text(50, 136,
        "Sistem de Detecție a Intruziunilor în Kubernetes",
        ha="center", va="center", fontsize=13, fontweight="bold")
ax.text(50, 132.5,
        "Arhitectură defense-in-depth (overview)",
        ha="center", va="center", fontsize=10, fontstyle="italic", color="#444444")


def rounded_box(x, y, w, h, label, facecolor, edgecolor, fontsize=8.5,
                fontweight="normal", title=None, title_fontsize=9):
    """Desenează un dreptunghi rotunjit cu text centrat."""
    box = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.15,rounding_size=0.6",
        facecolor=facecolor, edgecolor=edgecolor, linewidth=1.3,
    )
    ax.add_patch(box)
    if title:
        ax.text(x + w / 2, y + h - 1.6, title, ha="center", va="center",
                fontsize=title_fontsize, fontweight="bold")
        ax.text(x + w / 2, y + (h - 3.2) / 2 - 0.5, label, ha="center", va="center",
                fontsize=fontsize)
    else:
        ax.text(x + w / 2, y + h / 2, label, ha="center", va="center",
                fontsize=fontsize, fontweight=fontweight)


def arrow(x1, y1, x2, y2, label=None, color="#444444", lw=1.4, label_offset=(0, 0),
          label_fontsize=7.5):
    a = FancyArrowPatch(
        (x1, y1), (x2, y2),
        arrowstyle="-|>", mutation_scale=14, linewidth=lw,
        color=color, shrinkA=2, shrinkB=2,
    )
    ax.add_patch(a)
    if label:
        ax.text((x1 + x2) / 2 + label_offset[0],
                (y1 + y2) / 2 + label_offset[1],
                label, ha="center", va="center",
                fontsize=label_fontsize, color="#222222", fontstyle="italic",
                bbox=dict(facecolor="white", edgecolor="none", pad=0.5, alpha=0.85))


# ====================================================================
# NIVEL 1 (sus) — Cluster Kubernetes cu 3 planuri ca surse de date
# ====================================================================

# Container cluster K8s (mare, încapsulează cele 3 planuri)
cluster_x, cluster_y, cluster_w, cluster_h = 8, 105, 84, 23
rounded_box(cluster_x, cluster_y, cluster_w, cluster_h,
            label="", facecolor="#f5f5f5", edgecolor="#666666")
ax.text(cluster_x + cluster_w / 2, cluster_y + cluster_h - 1.7,
        "Cluster Kubernetes gestionat (AKS)",
        ha="center", va="center", fontsize=10, fontweight="bold")

# Cele 3 planuri-sursă (orizontal în interiorul cluster-ului)
plane_w, plane_h = 24, 14
plane_y = cluster_y + 2.5
spacing = (cluster_w - 3 * plane_w) / 4

rounded_box(cluster_x + spacing, plane_y, plane_w, plane_h,
            label="Plan rețea\n(trafic / fluxuri\nnetwork)",
            facecolor="#ffffff", edgecolor="#6c8ebf", fontsize=8)
rounded_box(cluster_x + 2 * spacing + plane_w, plane_y, plane_w, plane_h,
            label="Plan control / API\n(audit log\nAPI-server)",
            facecolor="#ffffff", edgecolor="#82b366", fontsize=8)
rounded_box(cluster_x + 3 * spacing + 2 * plane_w, plane_y, plane_w, plane_h,
            label="Plan runtime / container\n(syscalls în\ncontainer)",
            facecolor="#ffffff", edgecolor="#d79b00", fontsize=8)

# ====================================================================
# NIVEL 2 — Săgeți de la planuri către componente
# ====================================================================
# Y pentru top componente
comp_y_top = 84
comp_y_bot = 70
comp_w, comp_h = 24, 14

# Plane 1 → Flow
arrow(cluster_x + spacing + plane_w / 2, plane_y,
      cluster_x + spacing + plane_w / 2, comp_y_top + comp_h,
      label="fluxuri network", color="#6c8ebf", label_offset=(0, 0))
# Plane 2 → Audit
arrow(cluster_x + 2 * spacing + plane_w + plane_w / 2, plane_y,
      cluster_x + 2 * spacing + plane_w + plane_w / 2, comp_y_top + comp_h,
      label="kube-audit\n(Log Analytics)", color="#82b366", label_offset=(0, 0))
# Plane 3 → Falco
arrow(cluster_x + 3 * spacing + 2 * plane_w + plane_w / 2, plane_y,
      cluster_x + 3 * spacing + 2 * plane_w + plane_w / 2, comp_y_top + comp_h,
      label="syscalls (eBPF)", color="#d79b00", label_offset=(0, 0))

# ====================================================================
# NIVEL 3 — 3 componente de detecție (orizontal)
# ====================================================================
# Flow (albastru)
rounded_box(cluster_x + spacing, comp_y_bot, comp_w, comp_h,
            label="XGBoost + Autoencoder (ML)\natacuri de rețea / DDoS",
            facecolor="#dae8fc", edgecolor="#6c8ebf", fontsize=8,
            title="Componenta Flow", title_fontsize=9)
# Audit (verde)
rounded_box(cluster_x + 2 * spacing + plane_w, comp_y_bot, comp_w, comp_h,
            label="Transformer secvențial (ML)\nabuz în API-ul Kubernetes",
            facecolor="#d5e8d4", edgecolor="#82b366", fontsize=8,
            title="Componenta Audit", title_fontsize=9)
# Falco (portocaliu)
rounded_box(cluster_x + 3 * spacing + 2 * plane_w, comp_y_bot, comp_w, comp_h,
            label="Reguli eBPF (semnături)\nactivitate suspectă\nîn container",
            facecolor="#ffe6cc", edgecolor="#d79b00", fontsize=8,
            title="Componenta Falco", title_fontsize=9)

# ====================================================================
# NIVEL 4 — Săgeți de la componente către corelator
# ====================================================================
cor_y_top = 47
cor_y_bot = 30
cor_x = 30
cor_w = 40

# Centrul orizontal al corelator-ului
cor_center_x = cor_x + cor_w / 2

# 3 săgeți spre corelator
for plane_i in range(3):
    src_x = cluster_x + (plane_i + 1) * spacing + plane_i * plane_w + plane_w / 2
    if plane_i == 0:
        src_x = cluster_x + spacing + plane_w / 2
    elif plane_i == 1:
        src_x = cluster_x + 2 * spacing + plane_w + plane_w / 2
    else:
        src_x = cluster_x + 3 * spacing + 2 * plane_w + plane_w / 2
    arrow(src_x, comp_y_bot, cor_center_x, cor_y_top, color="#888888")

# ====================================================================
# NIVEL 5 — Corelator
# ====================================================================
rounded_box(cor_x, cor_y_bot, cor_w, cor_y_top - cor_y_bot,
            label="prag → calibrare Platt → corelare per actor →\n"
                  "lanțuri MITRE ATT&CK → severitate",
            facecolor="#e1d5e7", edgecolor="#9673a6", fontsize=8.2,
            title="Corelator de alerte (pipeline 5 niveluri)", title_fontsize=9)

# ====================================================================
# NIVEL 6 — Săgeată corelator → observabilitate
# ====================================================================
obs_y_top = 22
obs_y_bot = 7
obs_x = 28
obs_w = 44

arrow(cor_center_x, cor_y_bot, obs_x + obs_w / 2, obs_y_top,
      label="incidente corelate", color="#9673a6")

# ====================================================================
# NIVEL 7 — Observabilitate
# ====================================================================
rounded_box(obs_x, obs_y_bot, obs_w, obs_y_top - obs_y_bot,
            label="Prometheus + Grafana (dashboards SOC / MLOps)\n"
                  "Alertmanager → Email",
            facecolor="#f5f5f5", edgecolor="#666666", fontsize=8.5,
            title="Observabilitate", title_fontsize=9)

# ====================================================================
# Footer / legendă
# ====================================================================
ax.text(50, 3,
        "Surse de date (sus) → 3 componente de detecție → corelator → observabilitate + alerte.\n"
        "ML supervizat + nesupervizat: Flow, Audit  ·  Reguli / semnături: Falco.",
        ha="center", va="center", fontsize=8, fontstyle="italic", color="#555555")

# ====================================================================
# Salvare
# ====================================================================
plt.subplots_adjust(left=0.05, right=0.95, top=0.97, bottom=0.03)
plt.savefig(OUT, format="jpg", dpi=300, bbox_inches="tight", pad_inches=0.4,
            facecolor="white")
print(f"Saved {OUT}")
plt.close(fig)
