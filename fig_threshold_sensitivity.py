"""
fig_threshold_sensitivity.py
----------------------------
Produces the threshold-sensitivity figure for Section 5.8 of the paper.

Reads existing trained model JSON results from packet-analysis/ — does
NOT retrain anything.

Two-panel figure:
  Top    – F1 vs. threshold, one line per provider (best model per point,
           bidirectional direction).
  Bottom – Precision / Recall grouped bars at each threshold
           (best model per provider, bidirectional).

Expected directory layout under packet-analysis/:

    packet-analysis/
        chatgpt/
            0.05/{bidirectional,incoming,outgoing}_models_chatgpt
            0.1/ {bidirectional,incoming,outgoing}_models_chatgpt
            {bidirectional,incoming,outgoing}_models          <- 0.2s results
        claude/   (same layout)
        gemini/   (same layout)
        3providers/
            0.05/{bidirectional,incoming,outgoing}_models
            0.1/ {bidirectional,incoming,outgoing}_models
            {bidirectional,incoming,outgoing}_models          <- 0.2s all-LLM

Each JSON file has:
    {
      "dataset_info": {...},
      "models": {
        "random_forest": {"accuracy":..,"precision":..,"recall":..,"f1":..},
        "svm":           {...},
        "xgboost":       {...}
      }
    }

Usage:
    cd <repo root>
    python fig_threshold_sensitivity.py
    python fig_threshold_sensitivity.py --repo ./packet-analysis --out ./figures/

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
from matplotlib.patches import Patch
import numpy as np


# ── config ───────────────────────────────────────────────────────────────────

PROVIDERS  = ["chatgpt", "gemini", "claude"]
THRESHOLDS = [0.05, 0.1, 0.2]

PROVIDER_LABELS  = {"chatgpt": "ChatGPT", "gemini": "Gemini", "claude": "Claude"}
PROVIDER_COLORS  = {"chatgpt": "#4C72B0", "gemini": "#DD8452", "claude": "#55A868"}
PROVIDER_MARKERS = {"chatgpt": "o",       "gemini": "s",       "claude": "^"}

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
      - 0.05 and 0.1 live inside a threshold subdir, and filenames are
        suffixed with the provider (e.g. bidirectional_models_chatgpt).
      - 0.2 lives at the top level of the provider dir, and filenames
        are NOT suffixed (e.g. bidirectional_models).
    """
    if threshold == 0.2:
        path = os.path.join(repo, provider, f"{direction}_models")
    else:
        # str(0.05) -> "0.05", str(0.1) -> "0.1"
        path = os.path.join(
            repo, provider, str(threshold), f"{direction}_models_{provider}"
        )
    return path if os.path.isfile(path) else None


def load_result(path: str) -> dict:
    with open(path) as fh:
        return json.load(fh)


def best_model_metrics(repo: str, provider: str, threshold: float,
                       direction: str, metric: str = "f1") -> Optional[dict]:
    """Return the model dict with the highest `metric` for this slice."""
    path = resolve_path(repo, provider, threshold, direction)
    if path is None:
        print(f"  [warn] missing: {provider} / {threshold}s / {direction}",
              file=sys.stderr)
        return None
    try:
        data = load_result(path)
    except Exception as e:
        print(f"  [warn] failed to read {path}: {e}", file=sys.stderr)
        return None

    candidates = []
    for name, m in data.get("models", {}).items():
        if m.get(metric) is None:
            continue
        candidates.append({
            "model_name": name,
            "accuracy":   m.get("accuracy", 0.0),
            "precision":  m.get("precision", 0.0),
            "recall":     m.get("recall", 0.0),
            "f1":         m.get("f1", 0.0),
        })
    if not candidates:
        return None
    return max(candidates, key=lambda r: r.get(metric, 0))


# ── Panel A: F1 vs threshold line chart ──────────────────────────────────────

def plot_f1_lines(ax, repo: str):
    x = np.array(THRESHOLDS)

    for provider in PROVIDERS:
        f1_vals = []
        for thresh in THRESHOLDS:
            row = best_model_metrics(repo, provider, thresh, "bidirectional")
            f1_vals.append(row["f1"] if row else np.nan)

        ax.plot(
            x, f1_vals,
            marker=PROVIDER_MARKERS[provider],
            color=PROVIDER_COLORS[provider],
            linewidth=2.2,
            markersize=9,
            label=PROVIDER_LABELS[provider],
        )
        # value labels above each point
        for xi, yi in zip(x, f1_vals):
            if not np.isnan(yi):
                ax.annotate(
                    f"{yi:.3f}",
                    xy=(xi, yi),
                    xytext=(0, 10),
                    textcoords="offset points",
                    ha="center",
                    color=PROVIDER_COLORS[provider],
                    fontsize=8.5,
                )

    ax.set_xticks(THRESHOLDS)
    ax.set_xticklabels([f"{t:.2f} s" for t in THRESHOLDS])
    ax.set_xlabel(r"Flowlet timeout threshold  $\delta$", labelpad=6)
    ax.set_ylabel("F1 score")
    ax.set_title("(a)  F1 vs. threshold  (best model, bidirectional)",
                 fontsize=11)
    ax.set_ylim(0, 1.05)
    ax.yaxis.set_major_formatter(mtick.FormatStrFormatter("%.2f"))
    ax.legend(framealpha=0.85, loc="lower center", ncol=3)


# ── Panel B: Precision / Recall grouped bars ────────────────────────────────

def plot_prec_recall_bars(ax, repo: str):
    """
    For each threshold group, show precision and recall bars
    side-by-side for each provider (best model, bidirectional).
    """
    n_providers   = len(PROVIDERS)
    n_thresholds  = len(THRESHOLDS)
    bar_width     = 0.10
    group_gap     = 0.35
    threshold_cx  = np.arange(n_thresholds) * \
                    (n_providers * 2 * bar_width + group_gap)

    for p_idx, provider in enumerate(PROVIDERS):
        prec_vals, rec_vals = [], []
        for thresh in THRESHOLDS:
            row = best_model_metrics(repo, provider, thresh, "bidirectional")
            prec_vals.append(row["precision"] if row else 0)
            rec_vals.append(row["recall"]    if row else 0)

        base_off = (p_idx * 2) * bar_width - (n_providers - 1) * bar_width

        prec_x = threshold_cx + base_off
        rec_x  = threshold_cx + base_off + bar_width

        color = PROVIDER_COLORS[provider]
        label = PROVIDER_LABELS[provider]

        ax.bar(prec_x, prec_vals, width=bar_width, color=color,
               alpha=0.85, label=f"{label} Prec.")
        ax.bar(rec_x,  rec_vals,  width=bar_width, color=color,
               alpha=0.45, hatch="//", edgecolor=color, label=f"{label} Rec.")

    ax.set_xticks(threshold_cx)
    ax.set_xticklabels([rf"$\delta$ = {t:.2f} s" for t in THRESHOLDS])
    ax.set_ylabel("Score")
    ax.set_title("(b)  Precision (solid) vs. Recall (hatched) per threshold",
                 fontsize=11)
    ax.set_ylim(0, 1.15)
    ax.yaxis.set_major_formatter(mtick.FormatStrFormatter("%.2f"))

    # custom legend: one entry per provider + two for the pattern
    legend_elements = [
        Patch(facecolor=PROVIDER_COLORS[p], alpha=0.85,
              label=PROVIDER_LABELS[p])
        for p in PROVIDERS
    ]
    legend_elements += [
        Patch(facecolor="grey", alpha=0.85, label="Precision (solid)"),
        Patch(facecolor="grey", alpha=0.45, hatch="//",
              edgecolor="grey", label="Recall (hatched)"),
    ]
    ax.legend(handles=legend_elements, fontsize=9, ncol=2,
              loc="upper right", framealpha=0.85)


# ── debug printout ──────────────────────────────────────────────────────────

def print_summary_table(repo: str):
    """Print a plain-text summary of the metrics used in the figure."""
    print()
    print(f"{'Provider':<10} {'Threshold':>10} {'Model':<15}"
          f" {'Acc':>7} {'Prec':>7} {'Rec':>7} {'F1':>7}")
    print("-" * 68)
    for provider in PROVIDERS:
        for thresh in THRESHOLDS:
            row = best_model_metrics(repo, provider, thresh, "bidirectional")
            if row is None:
                print(f"{PROVIDER_LABELS[provider]:<10} "
                      f"{thresh:>10.2f} {'(missing)':<15}")
                continue
            print(f"{PROVIDER_LABELS[provider]:<10} "
                  f"{thresh:>10.2f} {row['model_name']:<15}"
                  f" {row['accuracy']:>7.3f} {row['precision']:>7.3f}"
                  f" {row['recall']:>7.3f} {row['f1']:>7.3f}")


# ── assemble and save ───────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo",
        default="./packet-analysis",
        help="Path to the packet-analysis directory (default: ./packet-analysis)",
    )
    parser.add_argument(
        "--out",
        default="./figures",
        help="Output directory for the figure (default: ./figures)",
    )
    parser.add_argument(
        "--formats",
        nargs="+",
        default=["pdf", "png"],
        help="Output formats (default: pdf png)",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.repo):
        sys.exit(f"[error] --repo path does not exist: {args.repo}")
    os.makedirs(args.out, exist_ok=True)

    print(f"Reading results from: {args.repo}")
    print_summary_table(args.repo)

    fig, (ax_top, ax_bottom) = plt.subplots(
        2, 1, figsize=(10, 10), constrained_layout=True
    )

    plot_f1_lines(ax_top, args.repo)
    plot_prec_recall_bars(ax_bottom, args.repo)

    for ext in args.formats:
        path = os.path.join(args.out, f"fig_threshold_sensitivity.{ext}")
        fig.savefig(path, bbox_inches="tight")
        print(f"\nSaved -> {path}")

    plt.close(fig)


if __name__ == "__main__":
    main()