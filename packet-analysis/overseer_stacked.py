#!/usr/bin/env python3
"""overseer_stacked.py

Mixture-of-experts overseer that learns how to combine provider-specific 
flowlet classifiers (ChatGPT, Claude, Gemini) for Sensitivity detection.

Level 0: Expert classifiers each producing P(sensitive | x).
Level 1: A meta-learner (XGBoost/GBM) trained on expert probabilities 
         plus interaction features (max, min, mean, std, spread).
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
except Exception:
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
    """Feature vector layout produced by ``build_meta_features``."""
    return [f"p_{name}" for name in expert_names] + list(AGGREGATE_FEATURE_NAMES)


def build_meta_features(expert_probs: np.ndarray) -> np.ndarray:
    """Augment raw expert probabilities with interaction terms."""
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
    """Produce honest out-of-fold ``P(sensitive)`` for every training flowlet."""
    groups = np.array(flowlet_groups(train_flowlets))
    y = flowlet_labels(train_flowlets)

    unique_groups = np.unique(groups)
    effective_splits = min(n_splits, len(unique_groups))
    if effective_splits < 2:
        raise ValueError(f"Not enough distinct flow groups. Only {len(unique_groups)} available.")

    gkf = GroupKFold(n_splits=effective_splits)
    oof = np.zeros((len(train_flowlets), len(experts)), dtype=float)

    for fold_idx, (tr_idx, va_idx) in enumerate(
        gkf.split(np.zeros(len(train_flowlets)), y, groups), start=1
    ):
        tr_flowlets = [train_flowlets[i] for i in tr_idx]
        va_flowlets = [train_flowlets[i] for i in va_idx]
        print(f"  fold {fold_idx}/{effective_splits}: train={len(tr_flowlets)}, val={len(va_flowlets)}")
        
        for j, exp in enumerate(experts):
            fold_expert = ExpertModel.for_provider(exp.name)
            try:
                fold_expert.fit(tr_flowlets, random_state=random_state)
            except ValueError:
                # Expert has no data in this fold; fallback to neutral
                oof[va_idx, j] = 0.5
                continue
            oof[va_idx, j] = fold_expert.predict_proba_sensitive(va_flowlets)

    return oof


def build_meta_learner(kind: str, random_state: int = 42):
    if kind == "xgboost":
        if not _HAS_XGB:
            raise RuntimeError("xgboost not installed.")
        return XGBClassifier(
            n_estimators=200,
            max_depth=3,
            learning_rate=0.1,
            random_state=random_state,
            eval_metric="logloss"
        )
    if kind == "gbm":
        from sklearn.ensemble import GradientBoostingClassifier
        return GradientBoostingClassifier(random_state=random_state)
    if kind == "logistic":
        return LogisticRegression(max_iter=1000, random_state=random_state)
    raise ValueError(f"Unknown meta-learner: {kind}")


def save_meta(meta: Any, kind: str, out_dir: Path, feature_names: Sequence[str]) -> Path:
    path = Path(out_dir) / "meta.pkl"
    joblib.dump({
        "meta": meta,
        "kind": kind,
        "feature_names": list(feature_names),
    }, path)
    return path


def load_meta(in_dir: Path) -> Tuple[Any, str, List[str]]:
    path = Path(in_dir) / "meta.pkl"
    if not path.exists():
        raise FileNotFoundError(f"Missing meta-learner: {path}")
    state = joblib.load(path)
    feature_names = state.get("feature_names", meta_feature_names(EXPERT_PROVIDERS))
    return state["meta"], state.get("kind", "unknown"), list(feature_names)


def _save_experts(experts: Sequence[ExpertModel], out_dir: Path) -> List[str]:
    saved = []
    for exp in experts:
        target = Path(out_dir) / "experts" / f"{exp.name}.pkl"
        exp.save(target)
        saved.append(str(target.relative_to(out_dir)))
    return saved


def _discover_saved_expert_names(load_dir: Path) -> List[str]:
    experts_dir = Path(load_dir) / "experts"
    if not experts_dir.is_dir(): return []
    present = {p.stem for p in experts_dir.glob("*.pkl")}
    ordered = [name for name in EXPERT_SOURCES if name in present]
    for name in sorted(present):
        if name not in ordered: ordered.append(name)
    return ordered


def _load_experts(load_dir: Path, providers: Optional[Sequence[str]] = None) -> List[ExpertModel]:
    if providers is None:
        providers = _discover_saved_expert_names(load_dir)
    experts = []
    for name in providers:
        path = Path(load_dir) / "experts" / f"{name}.pkl"
        experts.append(ExpertModel.from_saved(path))
    return experts


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Stacked MOE Overseer for Sensitivity detection.")
    p.add_argument("--snapshot-dir", default=None)
    p.add_argument("--snapshots-root", default=str(DEFAULT_SNAPSHOTS_ROOT))
    p.add_argument("--models-dir", default=str(DEFAULT_MODELS_ROOT))
    p.add_argument("--mode", choices=("train", "load"), default=None)
    p.add_argument("--load-dir", default=None)
    p.add_argument("--output", "-o", default=None)
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--cv-folds", type=int, default=5)
    p.add_argument("--meta", choices=("xgboost", "gbm", "logistic"), default="xgboost" if _HAS_XGB else "gbm")
    p.add_argument("--with-global-expert", action="store_true", help="Include expert trained on all providers.")
    p.add_argument("--random-state", type=int, default=42)
    p.add_argument("--non-interactive", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> None:
    args = parse_args(argv)
    snapshot_dir = Path(args.snapshot_dir).resolve() if args.snapshot_dir else prompt_snapshot_dir()
    mode = args.mode or prompt_mode()

    print(f"\nSnapshot: {snapshot_dir}\nMode: {mode}")

    flowlets = load_flowlets_from_snapshot(snapshot_dir)
    train_flowlets, test_flowlets = split_by_groups(flowlets, test_size=args.test_size, random_state=args.random_state)
    
    y_train = flowlet_labels(train_flowlets)
    y_test = flowlet_labels(test_flowlets)

    out_dir: Path | None = None
    load_dir: Path | None = None
    meta_kind: str = args.meta

    if mode == "train":
        out_dir = make_timestamped_dir(Path(args.models_dir), OVERSEER_PREFIX)
        expert_names = list(EXPERT_PROVIDERS)
        if args.with_global_expert:
            expert_names.append("all_providers")
        
        experts = build_experts(expert_names)

        print("\nGenerating OOF expert probabilities...")
        train_expert_probs = oof_expert_probabilities(experts, train_flowlets, n_splits=args.cv_folds, random_state=args.random_state)

        print("\nFitting final experts on full train split...")
        for exp in experts:
            exp.fit(train_flowlets, random_state=args.random_state)
        _save_experts(experts, out_dir)

        feature_names = meta_feature_names([e.name for e in experts])
        X_meta_train = build_meta_features(train_expert_probs)

        meta = build_meta_learner(args.meta, random_state=args.random_state)
        meta.fit(X_meta_train, y_train)
        save_meta(meta, args.meta, out_dir, feature_names)
    else:
        load_dir = Path(args.load_dir).resolve() if args.load_dir else prompt_load_dir(Path(args.models_dir), OVERSEER_PREFIX)
        experts = _load_experts(load_dir)
        meta, meta_kind, feature_names = load_meta(load_dir)

    # Evaluation
    test_expert_probs = stack_expert_probabilities(experts, test_flowlets)
    train_expert_probs_eval = stack_expert_probabilities(experts, train_flowlets)

    X_meta_train_eval = build_meta_features(train_expert_probs_eval)
    X_meta_test = build_meta_features(test_expert_probs)

    train_scores = meta.predict_proba(X_meta_train_eval)[:, 1]
    test_scores = meta.predict_proba(X_meta_test)[:, 1]
    
    overseer_metrics_train = compute_binary_metrics(y_train, (train_scores >= 0.5).astype(int), train_scores)
    overseer_metrics_test = compute_binary_metrics(y_test, (test_scores >= 0.5).astype(int), test_scores)

    # Metrics display
    for idx, exp in enumerate(experts):
        col = test_expert_probs[:, idx]
        print_metrics_block(f"EXPERT {exp.name.upper()}", compute_binary_metrics(y_test, (col >= 0.5).astype(int), col))
    
    print_metrics_block(f"OVERSEER (stacked-{meta_kind}) - TEST", overseer_metrics_test)

    # Save Results
    results = {
        "overseer": {
            "type": f"stacked_{meta_kind}",
            "experts": [exp.name for exp in experts],
            "test_metrics": overseer_metrics_test,
        },
        "dataset_info": {"snapshot": str(snapshot_dir), "train_count": len(train_flowlets), "test_count": len(test_flowlets)}
    }
    
    output_path = Path(args.output) if args.output else (out_dir or load_dir) / "overseer_stacked_results.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)


if __name__ == "__main__":
    main()