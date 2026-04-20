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

Two-panel figure:
  Left  – FPR vs. threshold, one line per provider (best model per point,
          bidirectional).
  Right – FNR vs. threshold, one line per provider (best model per point,
          bidirectional).

"Best model" is chosen by lowest FNR at each (provider, threshold) cell,
since LLM detection coverage is the primary concern. The selected model
is annotated next to each point.

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


# ── Panel A: FPR vs threshold ────────────────────────────────────────────────

def plot_rate_lines(ax, repo: str, metric: str, title: str):
    """
    metric: 'fpr' or 'fnr'
    """
    x = np.array(THRESHOLDS)

    for provider in PROVIDERS:
        vals, model_names = [], []
        for thresh in THRESHOLDS:
            row = best_model_rates(repo, provider, thresh)
            if row is None:
                vals.append(np.nan)
                model_names.append(None)
            else:
                vals.append(row[metric] * 100)   # convert to %
                model_names.append(row["model_name"])

        ax.plot(
            x, vals,
            marker=PROVIDER_MARKERS[provider],
            color=PROVIDER_COLORS[provider],
            linewidth=2.2,
            markersize=9,
            label=PROVIDER_LABELS[provider],
        )
        # value + model annotation above each point
        for xi, yi, mn in zip(x, vals, model_names):
            if np.isnan(yi):
                continue
            short = MODEL_SHORT.get(mn, mn)
            ax.annotate(
                f"{yi:.1f}%\n({short})",
                xy=(xi, yi),
                xytext=(0, 10),
                textcoords="offset points",
                ha="center",
                color=PROVIDER_COLORS[provider],
                fontsize=8,
            )

    ax.set_xticks(THRESHOLDS)
    ax.set_xticklabels([f"{t:.2f} s" for t in THRESHOLDS])
    ax.set_xlabel(r"Flowlet timeout threshold  $\delta$", labelpad=6)
    ax.set_ylabel(f"{metric.upper()} (%)")
    ax.set_title(title, fontsize=11)
    ax.yaxis.set_major_formatter(mtick.FormatStrFormatter("%.0f%%"))
    ax.legend(framealpha=0.85, loc="best")


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

    fig, (ax_left, ax_right) = plt.subplots(
        1, 2, figsize=(13, 5), constrained_layout=True
    )

    plot_rate_lines(
        ax_left, args.repo, "fpr",
        "(a)  FPR vs. threshold  (non-LLM flagged as LLM)",
    )
    plot_rate_lines(
        ax_right, args.repo, "fnr",
        "(b)  FNR vs. threshold  (LLM flowlets missed)",
    )

    for ext in args.formats:
        path = os.path.join(args.out, f"fig_fp_fn_rates.{ext}")
        fig.savefig(path, bbox_inches="tight")
        print(f"\nSaved -> {path}")

    plt.close(fig)


if __name__ == "__main__":
    main()