"""
fig_fp_fn_rates.py
------------------
Produces the false-positive / false-negative rate figure for Section 6.1.

Reads existing trained model JSON results from packet-analysis/ — does
NOT retrain anything.

Confusion matrix convention (from classification_report row order):
    row 0 = non_llm (negative class)
    row 1 = llm     (positive class)

    matrix = [[TN, FP],
              [FN, TP]]

    FPR = FP / (FP + TN)   — non-LLM flowlets flagged as LLM
    FNR = FN / (FN + TP)   — LLM flowlets missed

SINGLE-PANEL figure:
  FPR (solid lines, filled markers) and FNR (dashed lines, open markers)
  plotted on the same axes, one color per provider. Best model per
  (provider, threshold) cell, bidirectional direction.

The solid-vs-dashed + filled-vs-open distinction is designed so the two
rate types are instantly distinguishable even in grayscale printing.

Usage:
    cd <repo root>
    python fig_fp_fn_rates.py
    python fig_fp_fn_rates.py --repo ./packet-analysis --out ./figures/

Requirements:  matplotlib, numpy
    pip install matplotlib numpy
"""

import argparse
import json
import os
import sys
from typing import Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
import numpy as np


# ── config ───────────────────────────────────────────────────────────────────

PROVIDERS  = ["chatgpt", "gemini", "claude"]
THRESHOLDS = [0.05, 0.1, 0.2]

PROVIDER_LABELS  = {"chatgpt": "ChatGPT", "gemini": "Gemini", "claude": "Claude"}
PROVIDER_COLORS  = {"chatgpt": "#4C72B0", "gemini": "#DD8452", "claude": "#55A868"}
PROVIDER_MARKERS = {"chatgpt": "o",       "gemini": "s",       "claude": "^"}

MODEL_SHORT = {
    "random_forest": "RF",
    "xgboost":       "XGB",
    "svm":           "SVM",
}

plt.rcParams.update({
    "font.family":       "sans-serif",
    "font.size":         11,
    "axes.spines.top":   False,
    "axes.spines.right": False,
    "axes.grid":         True,
    "grid.alpha":        0.35,
    "grid.linestyle":    "--",
    "figure.dpi":        150,
})


# ── file resolution ──────────────────────────────────────────────────────────

def resolve_path(repo: str, provider: str, threshold: float,
                 direction: str) -> Optional[str]:
    """
    Map (provider, threshold, direction) -> file path.

    Layout quirks:
      - 0.05 and 0.1 live inside a threshold subdir. Filenames are
        provider-suffixed (e.g. bidirectional_models_chatgpt).
      - 0.2 lives at the top level of the provider dir with NO suffix
        (e.g. bidirectional_models).
    """
    if threshold == 0.2:
        path = os.path.join(repo, provider, f"{direction}_models")
    else:
        path = os.path.join(
            repo, provider, str(threshold), f"{direction}_models_{provider}"
        )
    return path if os.path.isfile(path) else None


def rates_from_matrix(cm) -> Optional[dict]:
    """cm = [[TN, FP], [FN, TP]]."""
    if (not isinstance(cm, list) or len(cm) != 2
            or len(cm[0]) != 2 or len(cm[1]) != 2):
        return None
    tn, fp = cm[0]
    fn, tp = cm[1]

    neg = tn + fp
    pos = fn + tp
    return {
        "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        "fpr": (fp / neg) if neg else float("nan"),
        "fnr": (fn / pos) if pos else float("nan"),
    }


def best_model_rates(repo: str, provider: str, threshold: float,
                     direction: str = "bidirectional") -> Optional[dict]:
    """
    Return {model_name, fpr, fnr, ...} for the model with the LOWEST FNR.
    Returns None if the file is missing or unparseable.
    """
    path = resolve_path(repo, provider, threshold, direction)
    if path is None:
        print(f"  [warn] missing: {provider} / {threshold}s / {direction}",
              file=sys.stderr)
        return None
    try:
        data = json.load(open(path))
    except Exception as e:
        print(f"  [warn] failed to read {path}: {e}", file=sys.stderr)
        return None

    candidates = []
    for name, m in data.get("models", {}).items():
        r = rates_from_matrix(m.get("confusion_matrix"))
        if r is None:
            continue
        candidates.append({"model_name": name, **r})

    if not candidates:
        return None
    return min(candidates, key=lambda r: r["fnr"])


# ── Combined FPR + FNR single-panel plot ────────────────────────────────────

def plot_combined(ax, repo: str):
    """
    One axes, two line styles:
      - FPR: SOLID line, FILLED markers, full opacity
      - FNR: DASHED line, OPEN (white-fill) markers, with "×" overlay

    Color = provider identity (consistent with other paper figures).
    Dashed+open makes FNR read as "less reliable / worse" at a glance.
    """
    x = np.array(THRESHOLDS)

    # Vertical offsets for FPR labels, staggered per provider at each
    # threshold so the cluster near 1–3% doesn't collide.
    fpr_label_offset = {"chatgpt": -14, "gemini": -14, "claude": -28}

    for provider in PROVIDERS:
        fpr_vals, fnr_vals, model_names = [], [], []
        for thresh in THRESHOLDS:
            row = best_model_rates(repo, provider, thresh)
            if row is None:
                fpr_vals.append(np.nan)
                fnr_vals.append(np.nan)
                model_names.append(None)
            else:
                fpr_vals.append(row["fpr"] * 100)
                fnr_vals.append(row["fnr"] * 100)
                model_names.append(row["model_name"])

        color  = PROVIDER_COLORS[provider]
        marker = PROVIDER_MARKERS[provider]
        label  = PROVIDER_LABELS[provider]

        # ---- FPR: solid, filled ----
        ax.plot(
            x, fpr_vals,
            linestyle="-", linewidth=2.4,
            marker=marker, markersize=10,
            markerfacecolor=color, markeredgecolor=color,
            color=color,
            label=f"{label} — FPR",
            zorder=3,
        )
        # Labels below for low-FPR providers, above for Gemini (which sits
        # high enough that below would collide with low-FPR labels).
        for xi, yi in zip(x, fpr_vals):
            if np.isnan(yi):
                continue
            if provider == "gemini":
                dy, va = 12, "bottom"
            else:
                dy, va = fpr_label_offset[provider], "top"
            ax.annotate(
                f"{yi:.1f}%",
                xy=(xi, yi),
                xytext=(0, dy),
                textcoords="offset points",
                ha="center", va=va,
                color=color, fontsize=8.5, fontweight="bold",
            )

        # ---- FNR: dashed, open markers ----
        ax.plot(
            x, fnr_vals,
            linestyle="--", linewidth=2.2,
            marker=marker, markersize=11,
            markerfacecolor="white", markeredgecolor=color,
            markeredgewidth=2.2,
            color=color,
            label=f"{label} — FNR",
            zorder=2,
        )
        for xi, yi in zip(x, fnr_vals):
            if not np.isnan(yi):
                ax.annotate(
                    f"{yi:.1f}%",
                    xy=(xi, yi),
                    xytext=(0, 11),
                    textcoords="offset points",
                    ha="center", va="bottom",
                    color=color, fontsize=8.5, fontweight="bold",
                )

    # Shaded backgrounds to further cue the two regimes visually
    ax.axhspan(0, 5, facecolor="#C8E6C9", alpha=0.25, zorder=0)
    ax.axhspan(20, 100, facecolor="#FFCDD2", alpha=0.18, zorder=0)

    # Annotated band labels
    ax.text(
        0.012, 2.5, "low FPR zone",
        color="#2E7D32", fontsize=8.5, style="italic",
        transform=ax.get_yaxis_transform(), ha="left", va="center",
    )
    ax.text(
        0.012, 32, "high FNR zone",
        color="#C62828", fontsize=8.5, style="italic",
        transform=ax.get_yaxis_transform(), ha="left", va="center",
    )

    ax.set_xticks(THRESHOLDS)
    ax.set_xticklabels([f"{t:.2f} s" for t in THRESHOLDS])
    ax.set_xlabel(r"Flowlet timeout threshold  $\delta$", labelpad=6)
    ax.set_ylabel("Rate (%)")
    ax.set_title(
        "False positive rate vs. false negative rate  "
        "(best model per cell, bidirectional)",
        fontsize=12, pad=10,
    )
    ax.yaxis.set_major_formatter(mtick.FormatStrFormatter("%.0f%%"))
    ax.set_ylim(-3, 45)
    ax.set_xlim(0.035, 0.215)

    # Two-column legend:
    #   - Column 1: the three providers (by color, shown as solid lines)
    #   - Column 2: the two rate types (by line style)
    from matplotlib.lines import Line2D
    provider_handles = [
        Line2D([0], [0], color=PROVIDER_COLORS[p], linewidth=2.5,
               marker=PROVIDER_MARKERS[p], markersize=9,
               markerfacecolor=PROVIDER_COLORS[p],
               label=PROVIDER_LABELS[p])
        for p in PROVIDERS
    ]
    style_handles = [
        Line2D([0], [0], color="black", linewidth=2.5, linestyle="-",
               marker="o", markersize=9, markerfacecolor="black",
               label="FPR  (solid, filled)"),
        Line2D([0], [0], color="black", linewidth=2.2, linestyle="--",
               marker="o", markersize=10, markerfacecolor="white",
               markeredgecolor="black", markeredgewidth=2,
               label="FNR  (dashed, open)"),
    ]

    leg1 = ax.legend(
        handles=provider_handles,
        title="Provider",
        loc="upper left", bbox_to_anchor=(1.01, 1.0),
        framealpha=0.9, fontsize=10, title_fontsize=10,
    )
    ax.add_artist(leg1)
    ax.legend(
        handles=style_handles,
        title="Rate type",
        loc="upper left", bbox_to_anchor=(1.01, 0.65),
        framealpha=0.9, fontsize=10, title_fontsize=10,
    )


# ── debug printout ──────────────────────────────────────────────────────────

def print_summary_table(repo: str):
    print()
    print(f"{'Provider':<10} {'δ (s)':>6} {'Model':<6} "
          f"{'FP':>6} {'FN':>6} {'FPR':>9} {'FNR':>9}")
    print("-" * 55)
    for provider in PROVIDERS:
        for thresh in THRESHOLDS:
            r = best_model_rates(repo, provider, thresh)
            if r is None:
                print(f"{PROVIDER_LABELS[provider]:<10} "
                      f"{thresh:>6.2f}  (missing)")
                continue
            short = MODEL_SHORT.get(r["model_name"], r["model_name"])
            print(f"{PROVIDER_LABELS[provider]:<10} "
                  f"{thresh:>6.2f} {short:<6} "
                  f"{r['fp']:>6d} {r['fn']:>6d} "
                  f"{r['fpr']*100:>7.2f} % "
                  f"{r['fnr']*100:>7.2f} %")


# ── assemble and save ───────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="./packet-analysis",
                    help="Path to packet-analysis/ (default: ./packet-analysis)")
    ap.add_argument("--out",  default="./figures",
                    help="Output directory (default: ./figures)")
    ap.add_argument("--formats", nargs="+", default=["pdf", "png"],
                    help="Output formats (default: pdf png)")
    args = ap.parse_args()

    if not os.path.isdir(args.repo):
        sys.exit(f"[error] --repo path does not exist: {args.repo}")
    os.makedirs(args.out, exist_ok=True)

    print(f"Reading results from: {args.repo}")
    print_summary_table(args.repo)

    fig, ax = plt.subplots(figsize=(11, 5.5), constrained_layout=True)
    plot_combined(ax, args.repo)

    for ext in args.formats:
        path = os.path.join(args.out, f"fig_fp_fn_rates.{ext}")
        fig.savefig(path, bbox_inches="tight")
        print(f"\nSaved -> {path}")

    plt.close(fig)


if __name__ == "__main__":
    main()