#!/usr/bin/env python3
"""overseer_stacked.py

Mixture-of-experts overseer that learns how to combine the three
provider-specific flowlet classifiers (ChatGPT, Claude, Gemini) instead
of falling back to a fixed rule like ``max``. This is a classic
*stacking* ensemble:

    level 0: three (optionally four) expert classifiers, each producing
             P(llm | x). The three per-provider experts are always
             included. An optional ``all_llm`` expert, trained on every
             LLM provider at once, can be added via
             ``--with-all-llm-expert``.
    level 1: a meta-learner (gradient-boosted trees by default) whose
             inputs are the expert probabilities plus a few interaction
             features (max, min, mean, std, spread).

Out-of-fold predictions (GroupKFold on flow 5-tuples) are used to train
the meta-learner so it never sees expert probabilities produced on the
experts' own training data. The final experts are then refit on the
full training split to score the held-out test set.

The main entry point walks the user through:
    1. Choosing a data snapshot under ``data-pipeline/data/snapshots/``
       (default = newest).
    2. Picking whether to (T)rain a new overseer on that snapshot or
       (L)oad a previously trained one from ``trained_overseers/``.
    3. Saving every fitted model (three experts + meta-learner) to a
       timestamped folder in ``trained_overseers/`` as PKL files.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupKFold

from overseer_common import (
    DEFAULT_MODELS_ROOT,
    DEFAULT_SNAPSHOTS_ROOT,
    EXPERT_PROVIDERS,
    EXPERT_SOURCES,
    ExpertModel,
    FlowletDict,
    build_experts,
    compute_binary_metrics,
    flowlet_groups,
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

try:
    from xgboost import XGBClassifier

    _HAS_XGB = True
except Exception:  # pragma: no cover - xgboost is optional
    _HAS_XGB = False


OVERSEER_PREFIX = "overseer_stacked"
AGGREGATE_FEATURE_NAMES: Tuple[str, ...] = (
    "max_p",
    "min_p",
    "mean_p",
    "std_p",
    "spread_p",
)


def meta_feature_names(expert_names: Sequence[str]) -> List[str]:
    """Feature vector layout produced by ``build_meta_features``.

    Length depends on how many experts are being stacked, so this is
    computed from the expert list rather than fixed at import time.
    """
    return [f"p_{name}" for name in expert_names] + list(AGGREGATE_FEATURE_NAMES)


def build_meta_features(expert_probs: np.ndarray) -> np.ndarray:
    """Augment the raw expert probabilities with simple interaction terms.

    Giving the meta-learner max/min/mean/spread in addition to the raw
    per-expert probabilities makes it easy for even a linear model to
    recover the ``max`` rule, while letting a tree model discover
    stronger combinations (e.g. "two experts agree").
    """
    if expert_probs.size == 0:
        return np.zeros((0, 0))
    max_p = expert_probs.max(axis=1, keepdims=True)
    min_p = expert_probs.min(axis=1, keepdims=True)
    mean_p = expert_probs.mean(axis=1, keepdims=True)
    std_p = expert_probs.std(axis=1, keepdims=True)
    spread = max_p - min_p
    return np.hstack([expert_probs, max_p, min_p, mean_p, std_p, spread])


def oof_expert_probabilities(
    experts: Sequence[ExpertModel],
    train_flowlets: Sequence[FlowletDict],
    n_splits: int = 5,
    random_state: int = 42,
) -> np.ndarray:
    """Produce honest out-of-fold ``P(llm)`` for every training flowlet.

    For each fold we fit each expert on the fold's training portion only
    (after applying the expert's provider filter) and predict on the
    held-out flowlets of *all* classes.
    """
    groups = np.array(flowlet_groups(train_flowlets))
    y = flowlet_labels(train_flowlets)

    unique_groups = np.unique(groups)
    effective_splits = min(n_splits, len(unique_groups))
    if effective_splits < 2:
        raise ValueError(
            "Not enough distinct flow groups to build OOF predictions; "
            f"only {len(unique_groups)} group(s) available."
        )

    gkf = GroupKFold(n_splits=effective_splits)
    oof = np.zeros((len(train_flowlets), len(experts)), dtype=float)

    for fold_idx, (tr_idx, va_idx) in enumerate(
        gkf.split(np.zeros(len(train_flowlets)), y, groups), start=1
    ):
        tr_flowlets = [train_flowlets[i] for i in tr_idx]
        va_flowlets = [train_flowlets[i] for i in va_idx]
        print(
            f"  fold {fold_idx}/{effective_splits}: "
            f"train={len(tr_flowlets)}, val={len(va_flowlets)}"
        )
        for j, exp in enumerate(experts):
            fold_expert = ExpertModel.for_provider(exp.name)
            try:
                fold_expert.fit(tr_flowlets, random_state=random_state)
            except ValueError:
                # Expert has no data in this fold (e.g. no non-LLM). Fall
                # back to a neutral 0.5 score for this fold.
                oof[va_idx, j] = 0.5
                continue
            oof[va_idx, j] = fold_expert.predict_proba_llm(va_flowlets)

    return oof


def build_meta_learner(kind: str, random_state: int = 42):
    if kind == "xgboost":
        if not _HAS_XGB:
            raise RuntimeError("xgboost is not installed; use --meta logistic or gbm")
        return XGBClassifier(
            n_estimators=200,
            max_depth=3,
            learning_rate=0.1,
            random_state=random_state,
            eval_metric="logloss",
            use_label_encoder=False,
        )
    if kind == "gbm":
        from sklearn.ensemble import GradientBoostingClassifier

        return GradientBoostingClassifier(random_state=random_state)
    if kind == "logistic":
        return LogisticRegression(max_iter=1000, random_state=random_state)
    raise ValueError(f"Unknown meta-learner kind: {kind}")


def save_meta(
    meta: Any,
    kind: str,
    out_dir: Path,
    feature_names: Sequence[str],
) -> Path:
    path = Path(out_dir) / "meta.pkl"
    joblib.dump(
        {
            "meta": meta,
            "kind": kind,
            "feature_names": list(feature_names),
        },
        path,
    )
    return path


def load_meta(in_dir: Path) -> Tuple[Any, str, List[str]]:
    path = Path(in_dir) / "meta.pkl"
    if not path.exists():
        raise FileNotFoundError(f"Missing meta-learner PKL: {path}")
    state = joblib.load(path)
    feature_names = state.get("feature_names")
    if not feature_names:
        # Legacy PKLs (pre-4th-expert) assumed the fixed 3-expert layout.
        feature_names = meta_feature_names(EXPERT_PROVIDERS)
    return state["meta"], state.get("kind", "unknown"), list(feature_names)


def _save_experts(experts: Sequence[ExpertModel], out_dir: Path) -> List[str]:
    saved: List[str] = []
    for exp in experts:
        target = Path(out_dir) / "experts" / f"{exp.name}.pkl"
        exp.save(target)
        saved.append(str(target.relative_to(out_dir)))
    return saved


def _discover_saved_expert_names(load_dir: Path) -> List[str]:
    """Return the expert names stored in ``<load_dir>/experts/*.pkl``.

    Order follows ``EXPERT_SOURCES`` so the column layout matches what
    ``build_experts`` would have produced at train time.
    """
    experts_dir = Path(load_dir) / "experts"
    if not experts_dir.is_dir():
        return []
    present = {p.stem for p in experts_dir.glob("*.pkl")}
    ordered = [name for name in EXPERT_SOURCES if name in present]
    # Preserve any experts that aren't in EXPERT_SOURCES (forward-compat).
    for name in sorted(present):
        if name not in ordered:
            ordered.append(name)
    return ordered


def _load_experts(
    load_dir: Path, providers: Optional[Sequence[str]] = None
) -> List[ExpertModel]:
    if providers is None:
        providers = _discover_saved_expert_names(load_dir)
    if not providers:
        raise FileNotFoundError(
            f"No expert PKLs found under {Path(load_dir) / 'experts'}"
        )
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
            "Stacked mixture-of-experts overseer that learns how to "
            "combine ChatGPT, Claude, and Gemini flowlet classifiers."
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
            "<models-dir or load-dir>/overseer_stacked_results.json."
        ),
    )
    p.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction of flows held out for evaluation (default: 0.2).",
    )
    p.add_argument(
        "--cv-folds",
        type=int,
        default=5,
        help="Group-aware CV folds for OOF expert predictions (default: 5).",
    )
    p.add_argument(
        "--meta",
        choices=("xgboost", "gbm", "logistic"),
        default="xgboost" if _HAS_XGB else "gbm",
        help="Meta-learner family (default: xgboost if installed else gbm).",
    )
    p.add_argument(
        "--with-all-llm-expert",
        action="store_true",
        help=(
            "Add a 4th expert trained on every LLM provider at once "
            "(plus non-LLM). Only applies in --mode train; on load, the "
            "expert set is read from the saved artifacts."
        ),
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


def _meta_model_info(
    meta: Any, feature_names: Sequence[str]
) -> Optional[Dict[str, Any]]:
    if hasattr(meta, "coef_"):
        return {
            "intercept": float(np.ravel(meta.intercept_)[0]),
            "coefficients": np.ravel(meta.coef_).tolist(),
            "feature_names": list(feature_names),
        }
    if hasattr(meta, "feature_importances_"):
        return {
            "feature_importances": np.asarray(meta.feature_importances_).tolist(),
            "feature_names": list(feature_names),
        }
    return None


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
    meta_kind: str = args.meta

    if mode == "train":
        out_dir = make_timestamped_dir(Path(args.models_dir), OVERSEER_PREFIX)
        print(f"\nTraining overseer. Artifacts will be saved to: {out_dir}")

        expert_names: List[str] = list(EXPERT_PROVIDERS)
        if args.with_all_llm_expert:
            expert_names.append("all_llm")
            print("  Including optional 'all_llm' expert (trained on every LLM).")
        experts = build_experts(expert_names)

        print("\nGenerating out-of-fold expert probabilities on the train split...")
        train_expert_probs = oof_expert_probabilities(
            experts,
            train_flowlets,
            n_splits=args.cv_folds,
            random_state=args.random_state,
        )

        print("\nFitting final experts on full train split...")
        for exp in experts:
            print(f"  Fitting expert: {exp.name}")
            exp.fit(train_flowlets, random_state=args.random_state)
        saved_expert_paths = _save_experts(experts, out_dir)
        print("  Saved expert PKLs:")
        for sp in saved_expert_paths:
            print(f"    {sp}")

        feature_names = meta_feature_names([e.name for e in experts])
        X_meta_train = build_meta_features(train_expert_probs)

        print(f"\nTraining meta-learner ({args.meta})...")
        meta = build_meta_learner(args.meta, random_state=args.random_state)
        meta.fit(X_meta_train, y_train)
        meta_path = save_meta(meta, args.meta, out_dir, feature_names)
        print(f"  Saved meta-learner PKL: {meta_path.relative_to(out_dir)}")
    else:
        load_dir = _resolve_load_dir(args)
        print(f"\nLoading overseer from: {load_dir}")
        experts = _load_experts(load_dir)
        meta, meta_kind, feature_names = load_meta(load_dir)
        print(
            f"  Loaded meta-learner kind: {meta_kind}; "
            f"experts: {[e.name for e in experts]}"
        )

    print("\nScoring the test split with every expert...")
    test_expert_probs = stack_expert_probabilities(experts, test_flowlets)
    train_expert_probs_eval = stack_expert_probabilities(experts, train_flowlets)

    X_meta_train_eval = build_meta_features(train_expert_probs_eval)
    X_meta_test = build_meta_features(test_expert_probs)

    train_scores = meta.predict_proba(X_meta_train_eval)[:, 1]
    test_scores = meta.predict_proba(X_meta_test)[:, 1]
    train_preds = (train_scores >= 0.5).astype(int)
    test_preds = (test_scores >= 0.5).astype(int)

    overseer_metrics_train = compute_binary_metrics(
        y_train, train_preds, train_scores
    )
    overseer_metrics_test = compute_binary_metrics(y_test, test_preds, test_scores)

    # Baseline: max rule on the same expert probabilities.
    if test_expert_probs.size:
        max_scores_test = test_expert_probs.max(axis=1)
    else:
        max_scores_test = np.zeros(0)
    max_preds_test = (max_scores_test >= 0.5).astype(int)
    max_metrics_test = compute_binary_metrics(y_test, max_preds_test, max_scores_test)

    expert_metrics_test: Dict[str, Dict[str, Any]] = {}
    for idx, exp in enumerate(experts):
        col = test_expert_probs[:, idx] if test_expert_probs.size else np.zeros(0)
        exp_preds = (col >= 0.5).astype(int)
        expert_metrics_test[exp.name] = compute_binary_metrics(y_test, exp_preds, col)

    for exp in experts:
        print_metrics_block(
            f"EXPERT {exp.name.upper()} (standalone on test set)",
            expert_metrics_test[exp.name],
        )
    print_metrics_block("BASELINE (max probability) - TEST", max_metrics_test)
    print_metrics_block(
        f"OVERSEER (stacked-{meta_kind}) - TRAIN", overseer_metrics_train
    )
    print_metrics_block(
        f"OVERSEER (stacked-{meta_kind}) - TEST", overseer_metrics_test
    )

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
            "type": f"stacked_{meta_kind}",
            "cv_folds": args.cv_folds if mode == "train" else None,
            "experts": [exp.name for exp in experts],
            "meta_model_info": _meta_model_info(meta, feature_names),
            "train_metrics": overseer_metrics_train,
            "test_metrics": overseer_metrics_test,
        },
        "baselines": {"max_probability_test": max_metrics_test},
        "individual_experts": expert_metrics_test,
        "dataset_info": dataset_info,
        "mode": mode,
        "artifacts_dir": str(out_dir) if out_dir else str(load_dir) if load_dir else None,
    }

    if mode == "train" and out_dir is not None:
        manifest = {
            "type": f"stacked_{meta_kind}",
            "experts": [exp.name for exp in experts],
            "meta_kind": meta_kind,
            "cv_folds": args.cv_folds,
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
        output_path = Path(target_dir) / "overseer_stacked_results.json"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)
    print(f"\nResults saved to {output_path}")
    if load_dir is not None:
        prior = read_manifest(load_dir)
        if prior:
            print(
                f"Loaded overseer was originally trained on: {prior.get('snapshot_dir')}"
            )


if __name__ == "__main__":
    main()
