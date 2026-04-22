#!/usr/bin/env python3
"""topic_classifier.py

Binary sensitive-topic classifier on encrypted LLM traffic metadata
(WhisperLeak replication on ChatGPT).

Input: MongoDB export JSON — an array of capture documents whose _id follows
the pattern ``<category>_<provider>_<threshold>``, e.g. ``drug_use_chatgpt_0.1``.
Each capture holds a nested list of flowlets.

Label: ``non_sensitive`` → 0, any of the five sensitive categories → 1.

Only ChatGPT traffic is used; flowlets whose ``llm_name`` is not ``CHATGPT`` are
dropped (this removes a small amount of Claude Code noise observed in the
``money_laundering_chatgpt_0.1`` capture).

Features (12 total, always the same length):
    8 aggregate: duration, packet_count, total_bytes,
                 inter_packet_time_mean/std, packet_size_mean/std,
                 direction_encoded
    4 Markov log-likelihoods: time-gap and size-block sequences scored under
                              sensitive and non-sensitive Markov models,
                              floored at -100.0 when a sequence is empty.

Splits train/test by flow 5-tuple via GroupShuffleSplit (no within-flow
leakage). Trains RF, SVM, XGBoost with class-balancing and reports
AUPRC, ROC-AUC, recall-at-FPR and per-category recall.
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import GroupShuffleSplit, StratifiedShuffleSplit
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

sys.path.insert(0, str(Path(__file__).resolve().parent))
from flowlet_models import (
    bucket_time_gaps,
    build_markov_model,
    build_power_law_blocks,
    compute_sequence_log_likelihood,
)

SENSITIVE_CATEGORIES = {
    "money_laundering",
    "drug_use",
    "legal_criminal",
    "weapons_firearms",
    "hacking_cybercrime",
}
NON_SENSITIVE_CATEGORY = "non_sensitive"
ALL_CATEGORIES = SENSITIVE_CATEGORIES | {NON_SENSITIVE_CATEGORY}

FEATURE_NAMES = [
    "duration",
    "packet_count",
    "total_bytes",
    "inter_packet_time_mean",
    "inter_packet_time_std",
    "packet_size_mean",
    "packet_size_std",
    "direction_encoded",
    "ll_time_sensitive",
    "ll_time_nonsensitive",
    "ll_size_sensitive",
    "ll_size_nonsensitive",
]

LL_FLOOR = -100.0


def parse_capture_id(cap_id: str) -> Tuple[str, str, str]:
    """Split ``<category>_<provider>_<threshold>`` from the tail end.

    Categories may contain underscores (e.g. ``money_laundering``), so split
    from the right.
    """
    parts = cap_id.rsplit("_", 2)
    if len(parts) != 3:
        return "", "", ""
    return parts[0], parts[1], parts[2]


def load_flowlets(
    filepath: str, threshold: str, provider: str = "chatgpt"
) -> List[Dict[str, Any]]:
    """Load flowlets for a single provider at a single threshold.

    Adds ``_category`` and ``_label`` to each flowlet. Drops flowlets whose
    ``llm_name`` disagrees with the requested provider.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        captures = json.load(f)

    wanted_llm = provider.upper()
    out: List[Dict[str, Any]] = []
    dropped_wrong_llm = 0

    for cap in captures:
        cap_id = cap.get("_id", "")
        category, cap_provider, cap_threshold = parse_capture_id(cap_id)
        if category not in ALL_CATEGORIES:
            continue
        if cap_provider != provider or cap_threshold != threshold:
            continue

        label = 0 if category == NON_SENSITIVE_CATEGORY else 1
        for fl in cap.get("flowlets", []):
            if fl.get("llm_name") != wanted_llm:
                dropped_wrong_llm += 1
                continue
            fl = dict(fl)
            fl["_category"] = category
            fl["_label"] = label
            fl["_capture_id"] = cap_id
            out.append(fl)

    if dropped_wrong_llm:
        print(
            f"  (dropped {dropped_wrong_llm} flowlets whose llm_name != {wanted_llm})"
        )
    return out


def build_markov_assets(
    flowlets: List[Dict[str, Any]],
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[float, str]]]:
    """Fit block mappings and Markov models on the training flowlets.

    Separate models per class (sensitive, non_sensitive). Only flowlets that
    actually carry raw arrays contribute.
    """
    by_class: Dict[str, List[Dict[str, Any]]] = {"sensitive": [], "non_sensitive": []}
    for fl in flowlets:
        key = "sensitive" if fl["_label"] == 1 else "non_sensitive"
        by_class[key].append(fl)

    block_mappings: Dict[str, Dict[float, str]] = {}
    for class_name, fls in by_class.items():
        all_sizes: List[float] = []
        for fl in fls:
            all_sizes.extend(fl.get("packet_sizes", []) or [])
        if all_sizes:
            _, mapping = build_power_law_blocks(all_sizes, coverage=0.9)
            block_mappings[class_name] = mapping

    markov_models: Dict[str, Dict[str, Any]] = {}
    for class_name, fls in by_class.items():
        time_seqs: List[List[str]] = []
        size_seqs: List[List[str]] = []
        for fl in fls:
            ipt = fl.get("inter_packet_times", []) or []
            if ipt:
                time_seqs.append(bucket_time_gaps(ipt))
            ps = fl.get("packet_sizes", []) or []
            if ps and class_name in block_mappings:
                mp = block_mappings[class_name]
                size_seqs.append([mp.get(s, f"BLOCK_{s:.2f}") for s in ps])
        markov_models[class_name] = {
            "time_gap": build_markov_model(time_seqs) if time_seqs else {},
            "size_block": build_markov_model(size_seqs) if size_seqs else {},
        }
    return markov_models, block_mappings


def featurize(
    fl: Dict[str, Any],
    markov_models: Dict[str, Dict[str, Any]],
    block_mappings: Dict[str, Dict[float, str]],
) -> np.ndarray:
    """Produce a fixed 12-feature vector for a flowlet."""
    feats: List[float] = [
        float(fl.get("duration", 0.0) or 0.0),
        float(fl.get("packet_count", 0) or 0),
        float(fl.get("total_bytes", 0) or 0),
        float(fl.get("inter_packet_time_mean", 0.0) or 0.0),
        float(fl.get("inter_packet_time_std", 0.0) or 0.0),
        float(fl.get("packet_size_mean", 0.0) or 0.0),
        float(fl.get("packet_size_std", 0.0) or 0.0),
        float(fl.get("direction_encoded", 0) or 0),
    ]

    ipt = fl.get("inter_packet_times", []) or []
    ps = fl.get("packet_sizes", []) or []
    time_seq = bucket_time_gaps(ipt) if ipt else []

    def _size_seq(class_name: str) -> List[str]:
        if not ps or class_name not in block_mappings:
            return []
        mp = block_mappings[class_name]
        return [mp.get(s, f"BLOCK_{s:.2f}") for s in ps]

    for class_name in ("sensitive", "non_sensitive"):
        mm = markov_models.get(class_name, {})
        time_mm = mm.get("time_gap") or {}
        if time_seq and time_mm:
            ll = compute_sequence_log_likelihood(time_seq, time_mm)
            feats.append(float(np.clip(ll, LL_FLOOR, 0.0)))
        else:
            feats.append(LL_FLOOR)

    for class_name in ("sensitive", "non_sensitive"):
        mm = markov_models.get(class_name, {})
        size_mm = mm.get("size_block") or {}
        sseq = _size_seq(class_name)
        if sseq and size_mm:
            ll = compute_sequence_log_likelihood(sseq, size_mm)
            feats.append(float(np.clip(ll, LL_FLOOR, 0.0)))
        else:
            feats.append(LL_FLOOR)

    return np.asarray(feats, dtype=np.float64)


def group_key(fl: Dict[str, Any]) -> str:
    """Group flowlets by their 5-tuple so no flow straddles train/test."""
    fk = fl.get("flow_key", {}) or {}
    return (
        f"{fk.get('src_ip', '')}|{fk.get('src_port', '')}|"
        f"{fk.get('dst_ip', '')}|{fk.get('dst_port', '')}|"
        f"{fk.get('protocol', '')}"
    )


def recall_at_fpr(y_true: np.ndarray, y_score: np.ndarray, target_fpr: float) -> float:
    """Max recall (TPR) achievable while keeping FPR ≤ target_fpr."""
    fpr, tpr, _ = roc_curve(y_true, y_score)
    ok = fpr <= target_fpr
    return float(tpr[ok].max()) if ok.any() else 0.0


def evaluate(
    name: str,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_score: np.ndarray,
) -> Dict[str, Any]:
    cm = confusion_matrix(y_true, y_pred).tolist()
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_score)),
        "auprc": float(average_precision_score(y_true, y_score)),
        "recall_at_5pct_fpr": recall_at_fpr(y_true, y_score, 0.05),
        "recall_at_10pct_fpr": recall_at_fpr(y_true, y_score, 0.10),
        "recall_at_20pct_fpr": recall_at_fpr(y_true, y_score, 0.20),
        "confusion_matrix": cm,
    }


def per_category_recall(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    categories: List[str],
) -> Dict[str, Dict[str, float]]:
    """Recall (or specificity, for non_sensitive) per category in the test set."""
    out: Dict[str, Dict[str, float]] = {}
    cats_arr = np.asarray(categories)
    for cat in sorted(set(categories)):
        mask = cats_arr == cat
        n = int(mask.sum())
        yt = y_true[mask]
        yp = y_pred[mask]
        if cat == NON_SENSITIVE_CATEGORY:
            # specificity: fraction of non-sensitive flowlets correctly classified
            correct = int((yp == 0).sum())
            out[cat] = {
                "count": n,
                "specificity": float(correct / n) if n else 0.0,
            }
        else:
            correct = int((yp == 1).sum())
            out[cat] = {
                "count": n,
                "recall": float(correct / n) if n else 0.0,
            }
    return out


def train_models(
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
) -> Tuple[Dict[str, Any], Dict[str, Any], StandardScaler]:
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    n_pos = int((y_train == 1).sum())
    n_neg = int((y_train == 0).sum())
    scale_pos_weight = (n_neg / n_pos) if n_pos else 1.0

    print(f"  class balance (train): {n_neg} neg / {n_pos} pos  "
          f"(scale_pos_weight={scale_pos_weight:.3f})")

    models: Dict[str, Any] = {}
    results: Dict[str, Any] = {}

    print("  [RF] fitting...")
    rf = RandomForestClassifier(
        n_estimators=500,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)
    y_score = rf.predict_proba(X_test)[:, 1]
    results["random_forest"] = evaluate("random_forest", y_test, y_pred, y_score)
    results["random_forest"]["y_score"] = y_score.tolist()
    results["random_forest"]["y_pred"] = y_pred.tolist()
    models["random_forest"] = rf

    print("  [SVM] fitting...")
    svm = SVC(
        kernel="rbf",
        class_weight="balanced",
        probability=True,
        random_state=42,
    )
    svm.fit(X_train_s, y_train)
    y_pred = svm.predict(X_test_s)
    y_score = svm.predict_proba(X_test_s)[:, 1]
    results["svm"] = evaluate("svm", y_test, y_pred, y_score)
    results["svm"]["y_score"] = y_score.tolist()
    results["svm"]["y_pred"] = y_pred.tolist()
    models["svm"] = svm

    print("  [XGB] fitting...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=500,
        max_depth=6,
        learning_rate=0.1,
        scale_pos_weight=scale_pos_weight,
        random_state=42,
        eval_metric="logloss",
        n_jobs=-1,
    )
    xgb_model.fit(X_train, y_train)
    y_pred = xgb_model.predict(X_test)
    y_score = xgb_model.predict_proba(X_test)[:, 1]
    results["xgboost"] = evaluate("xgboost", y_test, y_pred, y_score)
    results["xgboost"]["y_score"] = y_score.tolist()
    results["xgboost"]["y_pred"] = y_pred.tolist()
    models["xgboost"] = xgb_model

    return results, models, scaler


def main() -> None:
    p = argparse.ArgumentParser(
        description="Binary sensitive-topic classifier on ChatGPT flowlets."
    )
    p.add_argument("input", help="MongoDB export JSON")
    p.add_argument("--threshold", default="0.1",
                   help="flowlet threshold (default: 0.1)")
    p.add_argument("--provider", default="chatgpt",
                   help="provider to filter to (default: chatgpt)")
    p.add_argument("--output", "-o", default="topic_results.json")
    p.add_argument("--model-weights", default="topic_model_weights.pkl")
    p.add_argument("--test-size", type=float, default=0.3)
    p.add_argument(
        "--group-by-flow",
        action="store_true",
        help="split by 5-tuple group (may be unbalanced with few groups); "
             "default is stratified by category",
    )
    args = p.parse_args()

    print(f"Loading {args.input} (threshold={args.threshold}, "
          f"provider={args.provider})...")
    flowlets = load_flowlets(args.input, args.threshold, args.provider)
    if not flowlets:
        print("ERROR: no flowlets matched the filter.")
        sys.exit(1)

    by_cat: Dict[str, int] = defaultdict(int)
    for fl in flowlets:
        by_cat[fl["_category"]] += 1
    print("Per-category flowlet counts:")
    for cat in sorted(by_cat):
        print(f"  {cat:22s} {by_cat[cat]:5d}")

    categories = np.asarray([fl["_category"] for fl in flowlets])
    y_all = np.asarray([fl["_label"] for fl in flowlets])
    idx = np.arange(len(flowlets))

    if args.group_by_flow:
        groups = np.asarray([group_key(fl) for fl in flowlets])
        splitter = GroupShuffleSplit(
            n_splits=1, test_size=args.test_size, random_state=42
        )
        train_i, test_i = next(splitter.split(idx, y_all, groups))
        split_desc = "grouped by 5-tuple"
    else:
        # Stratify by fine-grained category so each class is represented
        # proportionally in train and test.
        splitter = StratifiedShuffleSplit(
            n_splits=1, test_size=args.test_size, random_state=42
        )
        train_i, test_i = next(splitter.split(idx, categories))
        split_desc = "stratified by category"

    train_flowlets = [flowlets[i] for i in train_i]
    test_flowlets = [flowlets[i] for i in test_i]

    print(f"\nSplit: {len(train_flowlets)} train / {len(test_flowlets)} test "
          f"({split_desc})")

    print("\nBuilding Markov models on training set only...")
    markov_models, block_mappings = build_markov_assets(train_flowlets)
    for cls, mm in markov_models.items():
        print(f"  {cls}: time_gap states={len(mm.get('time_gap', {}))}, "
              f"size_block states={len(mm.get('size_block', {}))}, "
              f"size-blocks={len(block_mappings.get(cls, {}))}")

    print("\nExtracting features...")
    X_train = np.vstack([featurize(fl, markov_models, block_mappings)
                         for fl in train_flowlets])
    X_test = np.vstack([featurize(fl, markov_models, block_mappings)
                        for fl in test_flowlets])
    y_train = np.asarray([fl["_label"] for fl in train_flowlets])
    y_test = np.asarray([fl["_label"] for fl in test_flowlets])
    cats_test = [fl["_category"] for fl in test_flowlets]

    print(f"  X_train shape: {X_train.shape}")
    print(f"  train pos/neg: {int((y_train==1).sum())} / {int((y_train==0).sum())}")
    print(f"  test  pos/neg: {int((y_test==1).sum())} / {int((y_test==0).sum())}")

    print("\nTraining models...")
    results, trained_models, scaler = train_models(X_train, X_test, y_train, y_test)

    print("\n" + "=" * 64)
    print(f"BINARY RESULTS  (threshold={args.threshold}, provider={args.provider})")
    print("=" * 64)
    for name, m in results.items():
        print(f"\n{name.upper()}")
        print(f"  AUPRC         : {m['auprc']:.4f}")
        print(f"  ROC-AUC       : {m['roc_auc']:.4f}")
        print(f"  Accuracy      : {m['accuracy']:.4f}")
        print(f"  Precision     : {m['precision']:.4f}")
        print(f"  Recall        : {m['recall']:.4f}")
        print(f"  F1            : {m['f1']:.4f}")
        print(f"  R@5%FPR       : {m['recall_at_5pct_fpr']:.4f}")
        print(f"  R@10%FPR      : {m['recall_at_10pct_fpr']:.4f}")
        print(f"  R@20%FPR      : {m['recall_at_20pct_fpr']:.4f}")
        cm = m["confusion_matrix"]
        print(f"  Confusion     : TN={cm[0][0]} FP={cm[0][1]} "
              f"FN={cm[1][0]} TP={cm[1][1]}")

    print("\nPer-category breakdown (using XGBoost):")
    xgb_pred = np.asarray(results["xgboost"]["y_pred"])
    per_cat = per_category_recall(y_test, xgb_pred, cats_test)
    for cat, d in per_cat.items():
        metric = "specificity" if cat == NON_SENSITIVE_CATEGORY else "recall"
        print(f"  {cat:22s} n={d['count']:4d}  {metric}={d[metric]:.4f}")

    out = {
        "dataset_info": {
            "threshold": args.threshold,
            "provider": args.provider,
            "total_flowlets": len(flowlets),
            "per_category_counts": dict(sorted(by_cat.items())),
            "train_size": int(len(train_flowlets)),
            "test_size": int(len(test_flowlets)),
            "train_pos_neg": [int((y_train == 1).sum()), int((y_train == 0).sum())],
            "test_pos_neg": [int((y_test == 1).sum()), int((y_test == 0).sum())],
            "feature_names": FEATURE_NAMES,
            "feature_dim": int(X_train.shape[1]),
        },
        "models": results,
        "per_category_xgb": per_cat,
        "y_test": y_test.tolist(),
        "categories_test": cats_test,
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(f"\nResults saved to {args.output}")

    artifacts = {
        "models": trained_models,
        "scaler": scaler,
        "markov_models": markov_models,
        "block_mappings": block_mappings,
        "feature_names": FEATURE_NAMES,
        "labels": {"non_sensitive": 0, "sensitive": 1},
        "training_metadata": {
            "input_file": str(args.input),
            "threshold": args.threshold,
            "provider": args.provider,
            "test_size": args.test_size,
        },
    }
    joblib.dump(artifacts, args.model_weights)
    print(f"Model artifacts saved to {args.model_weights}")


if __name__ == "__main__":
    main()
