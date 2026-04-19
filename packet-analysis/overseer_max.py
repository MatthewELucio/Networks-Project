#!/usr/bin/env python3
"""overseer_max.py

Mixture-of-experts overseer that fuses the three provider-specific
flowlet classifiers (ChatGPT, Claude, Gemini) by taking the maximum of
their LLM probabilities.

Intuition: each expert is a binary "is this one of MY provider's
flowlets?" detector. If any of them is confident the flowlet looks like
its provider's LLM traffic, the overseer declares the flowlet
LLM-generated. Formally:

    P_overseer(llm | x) = max(P_chatgpt, P_claude, P_gemini)
    y_hat = 1 if P_overseer >= threshold else 0

The main entry point walks the user through:
    1. Choosing a data snapshot under ``data-pipeline/data/snapshots/``
       (default = newest).
    2. Picking whether to (T)rain new experts on that snapshot or (L)oad
       a previously trained overseer from ``trained_overseers/``.
    3. Evaluating the overseer on a group-aware held-out split and
       writing both a JSON results file and (for training runs) PKL
       artifacts in a timestamped folder.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Sequence

import numpy as np

from overseer_common import (
    DEFAULT_MODELS_ROOT,
    DEFAULT_SNAPSHOTS_ROOT,
    EXPERT_PROVIDERS,
    ExpertModel,
    build_experts,
    compute_binary_metrics,
    flowlet_labels,
    latest_snapshot,
    load_flowlets_from_snapshot,
    make_timestamped_dir,
    print_metrics_block,
    prompt_load_dir,
    prompt_mode,
    prompt_snapshot_dir,
    read_manifest,
    split_by_groups,
    stack_expert_probabilities,
    write_manifest,
)


OVERSEER_PREFIX = "overseer_max"


def predict_max(
    expert_probs: np.ndarray, threshold: float = 0.5
) -> tuple[np.ndarray, np.ndarray]:
    """Combine per-expert ``P(llm)`` columns via elementwise max."""
    if expert_probs.size == 0:
        return np.zeros(0, dtype=float), np.zeros(0, dtype=int)
    scores = expert_probs.max(axis=1)
    preds = (scores >= threshold).astype(int)
    return scores, preds


def _save_experts(experts: Sequence[ExpertModel], out_dir: Path) -> List[str]:
    saved: List[str] = []
    for exp in experts:
        target = Path(out_dir) / "experts" / f"{exp.name}.pkl"
        exp.save(target)
        saved.append(str(target.relative_to(out_dir)))
    return saved


def _load_experts(
    load_dir: Path, providers: Sequence[str] = EXPERT_PROVIDERS
) -> List[ExpertModel]:
    experts: List[ExpertModel] = []
    for name in providers:
        path = Path(load_dir) / "experts" / f"{name}.pkl"
        if not path.exists():
            raise FileNotFoundError(f"Missing expert PKL: {path}")
        experts.append(ExpertModel.from_saved(path))
    return experts


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Max-probability mixture-of-experts overseer combining "
            "ChatGPT, Claude, and Gemini flowlet classifiers."
        )
    )
    p.add_argument(
        "--snapshot-dir",
        default=None,
        help=(
            "Snapshot directory (contains captures/*.json). "
            "Defaults to the newest snapshot under data-pipeline/data/snapshots."
        ),
    )
    p.add_argument(
        "--snapshots-root",
        default=str(DEFAULT_SNAPSHOTS_ROOT),
        help="Root directory holding snapshot folders (default: repo standard).",
    )
    p.add_argument(
        "--models-dir",
        default=str(DEFAULT_MODELS_ROOT),
        help="Directory where trained overseer folders are saved/loaded from.",
    )
    p.add_argument(
        "--mode",
        choices=("train", "load"),
        default=None,
        help="Train new models or load existing PKLs. Prompted if omitted.",
    )
    p.add_argument(
        "--load-dir",
        default=None,
        help=(
            "When --mode load, the overseer folder to load from. "
            "Prompted if omitted."
        ),
    )
    p.add_argument(
        "--output",
        "-o",
        default=None,
        help=(
            "Path for the JSON results file. Defaults to "
            "<models-dir or load-dir>/overseer_max_results.json."
        ),
    )
    p.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction of flows held out for evaluation (default: 0.2).",
    )
    p.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Decision threshold on the combined probability (default: 0.5).",
    )
    p.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for splits/estimators (default: 42).",
    )
    p.add_argument(
        "--non-interactive",
        action="store_true",
        help="Disable interactive prompts; use defaults/CLI args only.",
    )
    return p.parse_args(argv)


def _resolve_snapshot_dir(args: argparse.Namespace) -> Path:
    if args.snapshot_dir:
        return Path(args.snapshot_dir).expanduser().resolve()
    snapshots_root = Path(args.snapshots_root).expanduser().resolve()
    if args.non_interactive:
        snap = latest_snapshot(snapshots_root)
        if snap is None:
            raise SystemExit(
                f"No snapshots found under {snapshots_root}; pass --snapshot-dir."
            )
        return snap
    return prompt_snapshot_dir(snapshots_root=snapshots_root)


def _resolve_mode(args: argparse.Namespace) -> str:
    if args.mode is not None:
        return args.mode
    if args.non_interactive:
        return "train"
    return prompt_mode()


def _resolve_load_dir(args: argparse.Namespace) -> Path:
    if args.load_dir:
        return Path(args.load_dir).expanduser().resolve()
    models_root = Path(args.models_dir).expanduser().resolve()
    if args.non_interactive:
        dirs = sorted(
            (d for d in models_root.glob(f"{OVERSEER_PREFIX}_*") if d.is_dir()),
            key=lambda p: p.name,
        )
        if not dirs:
            raise SystemExit(
                f"No trained overseers with prefix '{OVERSEER_PREFIX}' under {models_root}."
            )
        return dirs[-1]
    return prompt_load_dir(models_root=models_root, prefix=OVERSEER_PREFIX)


def main(argv=None) -> None:
    args = parse_args(argv)

    snapshot_dir = _resolve_snapshot_dir(args)
    mode = _resolve_mode(args)

    print(f"\nSnapshot:   {snapshot_dir}")
    print(f"Mode:       {mode}")

    print("\nLoading flowlets from snapshot...")
    flowlets = load_flowlets_from_snapshot(snapshot_dir)
    print(f"Loaded {len(flowlets)} flowlets")

    train_flowlets, test_flowlets = split_by_groups(
        flowlets, test_size=args.test_size, random_state=args.random_state
    )
    print(f"Train set: {len(train_flowlets)} flowlets")
    print(f"Test set:  {len(test_flowlets)} flowlets")

    y_train = flowlet_labels(train_flowlets)
    y_test = flowlet_labels(test_flowlets)
    print(f"Train class distribution: {np.bincount(y_train, minlength=2).tolist()}")
    print(f"Test  class distribution: {np.bincount(y_test,  minlength=2).tolist()}")

    out_dir: Path | None = None
    load_dir: Path | None = None

    if mode == "train":
        out_dir = make_timestamped_dir(Path(args.models_dir), OVERSEER_PREFIX)
        print(f"\nTraining overseer. Artifacts will be saved to: {out_dir}")
        experts = build_experts()
        for exp in experts:
            print(f"  Fitting expert: {exp.name}")
            exp.fit(train_flowlets, random_state=args.random_state)
        saved_paths = _save_experts(experts, out_dir)
        print("  Saved PKLs:")
        for sp in saved_paths:
            print(f"    {sp}")
    else:
        load_dir = _resolve_load_dir(args)
        print(f"\nLoading overseer from: {load_dir}")
        experts = _load_experts(load_dir)

    print("\nScoring held-out flowlets with every expert...")
    test_probs = stack_expert_probabilities(experts, test_flowlets)
    train_probs = stack_expert_probabilities(experts, train_flowlets)

    scores_test, preds_test = predict_max(test_probs, threshold=args.threshold)
    scores_train, preds_train = predict_max(train_probs, threshold=args.threshold)

    overseer_metrics_test = compute_binary_metrics(y_test, preds_test, scores_test)
    overseer_metrics_train = compute_binary_metrics(
        y_train, preds_train, scores_train
    )

    expert_metrics: Dict[str, Dict[str, Any]] = {}
    for idx, exp in enumerate(experts):
        col = test_probs[:, idx] if test_probs.size else np.zeros(0)
        exp_preds = (col >= args.threshold).astype(int)
        expert_metrics[exp.name] = compute_binary_metrics(y_test, exp_preds, col)

    for exp in experts:
        print_metrics_block(
            f"EXPERT {exp.name.upper()} (standalone on test set)",
            expert_metrics[exp.name],
        )
    print_metrics_block("OVERSEER (max probability) - TRAIN", overseer_metrics_train)
    print_metrics_block("OVERSEER (max probability) - TEST", overseer_metrics_test)

    dataset_info = {
        "snapshot_dir": str(snapshot_dir),
        "total_flowlets": len(flowlets),
        "train_size": len(train_flowlets),
        "test_size": len(test_flowlets),
        "train_class_distribution": np.bincount(y_train, minlength=2).tolist(),
        "test_class_distribution": np.bincount(y_test, minlength=2).tolist(),
    }

    output_data = {
        "overseer": {
            "type": "max_probability",
            "threshold": args.threshold,
            "experts": [exp.name for exp in experts],
            "train_metrics": overseer_metrics_train,
            "test_metrics": overseer_metrics_test,
        },
        "individual_experts": expert_metrics,
        "dataset_info": dataset_info,
        "mode": mode,
        "artifacts_dir": str(out_dir) if out_dir else str(load_dir) if load_dir else None,
    }

    if mode == "train" and out_dir is not None:
        manifest = {
            "type": "max_probability",
            "experts": [exp.name for exp in experts],
            "threshold": args.threshold,
            "random_state": args.random_state,
            "test_size": args.test_size,
            "snapshot_dir": str(snapshot_dir),
            "dataset_info": dataset_info,
            "test_metrics": overseer_metrics_test,
        }
        write_manifest(out_dir, manifest)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
    else:
        target_dir = out_dir if out_dir is not None else load_dir
        if target_dir is None:
            target_dir = Path.cwd()
        output_path = Path(target_dir) / "overseer_max_results.json"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)
    print(f"\nResults saved to {output_path}")
    if load_dir is not None:
        prior = read_manifest(load_dir)
        if prior:
            print(f"Loaded overseer was originally trained on: {prior.get('snapshot_dir')}")


if __name__ == "__main__":
    main()
