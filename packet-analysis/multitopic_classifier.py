#!/usr/bin/env python3
"""multitopic_classifier.py

5-way classifier over the five sensitive categories (no non-sensitive control).

Input: MongoDB export JSON — same schema as topic_classifier.py.
Classes: money_laundering, drug_use, legal_criminal, weapons_firearms, hacking_cybercrime
Chance = 0.20 (accuracy) and ~0.20 (macro-F1 if balanced).

Features (18 total):
    8 aggregate: duration, packet_count, total_bytes,
                 inter_packet_time_mean/std, packet_size_mean/std,
                 direction_encoded
    10 Markov log-likelihoods: per class (5), time-gap and size-block
                               sequences scored under each class's Markov
                               model. Floored at -100.0.
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
    confusion_matrix,
    f1_score,
    classification_report,
)
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

sys.path.insert(0, str(Path(__file__).resolve().parent))
from flowlet_models import (
    bucket_time_gaps,
    build_markov_model,
    build_power_law_blocks,
    compute_sequence_log_likelihood,
)

SENSITIVE_CATEGORIES = [
    "money_laundering",
    "drug_use",
    "legal_criminal",
    "weapons_firearms",
    "hacking_cybercrime",
]
CAT_TO_IDX = {c: i for i, c in enumerate(SENSITIVE_CATEGORIES)}
IDX_TO_CAT = {i: c for c, i in CAT_TO_IDX.items()}

LL_FLOOR = -100.0

AGGREGATE_FEATURES = [
    "duration",
    "packet_count",
    "total_bytes",
    "inter_packet_time_mean",
    "inter_packet_time_std",
    "packet_size_mean",
    "packet_size_std",
    "direction_encoded",
]
FEATURE_NAMES = list(AGGREGATE_FEATURES)
for cat in SENSITIVE_CATEGORIES:
    FEATURE_NAMES.append(f"ll_time_{cat}")
    FEATURE_NAMES.append(f"ll_size_{cat}")


def parse_capture_id(cap_id: str) -> Tuple[str, str, str]:
    parts = cap_id.rsplit("_", 2)
    if len(parts) != 3:
        return "", "", ""
    return parts[0], parts[1], parts[2]


def load_flowlets(
    filepath: str, threshold: str, provider: str = "chatgpt"
) -> List[Dict[str, Any]]:
    with open(filepath, "r", encoding="utf-8") as f:
        captures = json.load(f)

    wanted_llm = provider.upper()
    out: List[Dict[str, Any]] = []
    dropped = 0
    for cap in captures:
        cap_id = cap.get("_id", "")
        category, cap_provider, cap_threshold = parse_capture_id(cap_id)
        if category not in CAT_TO_IDX:
            continue
        if cap_provider != provider or cap_threshold != threshold:
            continue
        for fl in cap.get("flowlets", []):
            if fl.get("llm_name") != wanted_llm:
                dropped += 1
                continue
            fl = dict(fl)
            fl["_category"] = category
            fl["_label"] = CAT_TO_IDX[category]
            out.append(fl)
    if dropped:
        print(f"  (dropped {dropped} flowlets whose llm_name != {wanted_llm})")
    return out


def build_markov_assets(
    flowlets: List[Dict[str, Any]],
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[float, str]]]:
    """One Markov model per sensitive category."""
    by_class: Dict[str, List[Dict[str, Any]]] = {c: [] for c in SENSITIVE_CATEGORIES}
    for fl in flowlets:
        by_class[fl["_category"]].append(fl)

    block_mappings: Dict[str, Dict[float, str]] = {}
    for cat, fls in by_class.items():
        sizes: List[float] = []
        for fl in fls:
            sizes.extend(fl.get("packet_sizes", []) or [])
        if sizes:
            _, mapping = build_power_law_blocks(sizes, coverage=0.9)
            block_mappings[cat] = mapping

    markov_models: Dict[str, Dict[str, Any]] = {}
    for cat, fls in by_class.items():
        time_seqs: List[List[str]] = []
        size_seqs: List[List[str]] = []
        for fl in fls:
            ipt = fl.get("inter_packet_times", []) or []
            if ipt:
                time_seqs.append(bucket_time_gaps(ipt))
            ps = fl.get("packet_sizes", []) or []
            if ps and cat in block_mappings:
                mp = block_mappings[cat]
                size_seqs.append([mp.get(s, f"BLOCK_{s:.2f}") for s in ps])
        markov_models[cat] = {
            "time_gap": build_markov_model(time_seqs) if time_seqs else {},
            "size_block": build_markov_model(size_seqs) if size_seqs else {},
        }
    return markov_models, block_mappings


def featurize(
    fl: Dict[str, Any],
    markov_models: Dict[str, Dict[str, Any]],
    block_mappings: Dict[str, Dict[float, str]],
) -> np.ndarray:
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

    for cat in SENSITIVE_CATEGORIES:
        mm = markov_models.get(cat, {})
        time_mm = mm.get("time_gap") or {}
        if time_seq and time_mm:
            ll = compute_sequence_log_likelihood(time_seq, time_mm)
            feats.append(float(np.clip(ll, LL_FLOOR, 0.0)))
        else:
            feats.append(LL_FLOOR)

        size_mm = mm.get("size_block") or {}
        if ps and cat in block_mappings and size_mm:
            mp = block_mappings[cat]
            sseq = [mp.get(s, f"BLOCK_{s:.2f}") for s in ps]
            ll = compute_sequence_log_likelihood(sseq, size_mm)
            feats.append(float(np.clip(ll, LL_FLOOR, 0.0)))
        else:
            feats.append(LL_FLOOR)
    return np.asarray(feats, dtype=np.float64)


def train_models(
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
) -> Tuple[Dict[str, Any], Dict[str, Any], StandardScaler]:
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    models: Dict[str, Any] = {}
    results: Dict[str, Any] = {}

    def record(name: str, y_pred: np.ndarray) -> None:
        report = classification_report(
            y_test, y_pred,
            labels=list(range(len(SENSITIVE_CATEGORIES))),
            target_names=SENSITIVE_CATEGORIES,
            output_dict=True,
            zero_division=0,
        )
        results[name] = {
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "macro_f1": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
            "weighted_f1": float(f1_score(y_test, y_pred, average="weighted", zero_division=0)),
            "per_class_f1": {
                cat: float(report[cat]["f1-score"]) for cat in SENSITIVE_CATEGORIES
            },
            "per_class_recall": {
                cat: float(report[cat]["recall"]) for cat in SENSITIVE_CATEGORIES
            },
            "per_class_precision": {
                cat: float(report[cat]["precision"]) for cat in SENSITIVE_CATEGORIES
            },
            "confusion_matrix": confusion_matrix(
                y_test, y_pred, labels=list(range(len(SENSITIVE_CATEGORIES)))
            ).tolist(),
            "y_pred": y_pred.tolist(),
        }

    print("  [RF] fitting...")
    rf = RandomForestClassifier(
        n_estimators=500, class_weight="balanced",
        random_state=42, n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    record("random_forest", rf.predict(X_test))
    models["random_forest"] = rf

    print("  [SVM] fitting...")
    svm = SVC(kernel="rbf", class_weight="balanced", random_state=42)
    svm.fit(X_train_s, y_train)
    record("svm", svm.predict(X_test_s))
    models["svm"] = svm

    print("  [XGB] fitting...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=500, max_depth=6, learning_rate=0.1,
        objective="multi:softprob",
        num_class=len(SENSITIVE_CATEGORIES),
        random_state=42, eval_metric="mlogloss", n_jobs=-1,
    )
    xgb_model.fit(X_train, y_train)
    record("xgboost", xgb_model.predict(X_test))
    models["xgboost"] = xgb_model

    return results, models, scaler


def main() -> None:
    p = argparse.ArgumentParser(description="5-way sensitive-topic classifier.")
    p.add_argument("input")
    p.add_argument("--threshold", default="0.1")
    p.add_argument("--provider", default="chatgpt")
    p.add_argument("--output", "-o", default="multitopic_results.json")
    p.add_argument("--model-weights", default="multitopic_model_weights.pkl")
    p.add_argument("--test-size", type=float, default=0.3)
    args = p.parse_args()

    print(f"Loading {args.input} (threshold={args.threshold})...")
    flowlets = load_flowlets(args.input, args.threshold, args.provider)
    if not flowlets:
        print("ERROR: no flowlets matched filter.")
        sys.exit(1)

    counts: Dict[str, int] = defaultdict(int)
    for fl in flowlets:
        counts[fl["_category"]] += 1
    print("Per-category flowlets:")
    for cat in SENSITIVE_CATEGORIES:
        print(f"  {cat:22s} {counts[cat]:5d}")

    idx = np.arange(len(flowlets))
    categories = np.asarray([fl["_category"] for fl in flowlets])
    gss = StratifiedShuffleSplit(
        n_splits=1, test_size=args.test_size, random_state=42
    )
    train_i, test_i = next(gss.split(idx, categories))
    train_fl = [flowlets[i] for i in train_i]
    test_fl = [flowlets[i] for i in test_i]

    print(f"\nSplit: {len(train_fl)} train / {len(test_fl)} test (stratified)")

    print("\nBuilding Markov models on training set only...")
    markov_models, block_mappings = build_markov_assets(train_fl)
    for cat in SENSITIVE_CATEGORIES:
        mm = markov_models.get(cat, {})
        print(f"  {cat:22s} time={len(mm.get('time_gap', {}))} "
              f"size={len(mm.get('size_block', {}))} "
              f"blocks={len(block_mappings.get(cat, {}))}")

    print("\nExtracting features...")
    X_train = np.vstack([featurize(fl, markov_models, block_mappings)
                         for fl in train_fl])
    X_test = np.vstack([featurize(fl, markov_models, block_mappings)
                        for fl in test_fl])
    y_train = np.asarray([fl["_label"] for fl in train_fl])
    y_test = np.asarray([fl["_label"] for fl in test_fl])
    print(f"  X shape: train={X_train.shape}, test={X_test.shape}")

    print("\nTraining models...")
    results, trained_models, scaler = train_models(X_train, X_test, y_train, y_test)

    print("\n" + "=" * 64)
    print("5-WAY RESULTS  (chance = 0.200)")
    print("=" * 64)
    for name, m in results.items():
        print(f"\n{name.upper()}")
        print(f"  Accuracy   : {m['accuracy']:.4f}")
        print(f"  Macro-F1   : {m['macro_f1']:.4f}")
        print(f"  Weighted-F1: {m['weighted_f1']:.4f}")
        print(f"  Per-class F1:")
        for cat in SENSITIVE_CATEGORIES:
            print(f"    {cat:22s} {m['per_class_f1'][cat]:.4f}")

    out = {
        "dataset_info": {
            "threshold": args.threshold,
            "provider": args.provider,
            "classes": SENSITIVE_CATEGORIES,
            "per_category_counts": {c: counts[c] for c in SENSITIVE_CATEGORIES},
            "train_size": int(len(train_fl)),
            "test_size": int(len(test_fl)),
            "feature_names": FEATURE_NAMES,
            "feature_dim": int(X_train.shape[1]),
        },
        "models": results,
        "y_test": y_test.tolist(),
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
        "classes": SENSITIVE_CATEGORIES,
        "label_to_category": IDX_TO_CAT,
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
