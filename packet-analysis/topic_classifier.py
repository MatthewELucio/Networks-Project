#!/usr/bin/env python3
"""topic_classifier.py

Train classification models to distinguish sensitive-topic vs non-sensitive
LLM traffic from encrypted packet metadata. This is the core WhisperLeak
replication: can a passive network observer tell what topic a user is
discussing with an LLM?

Input: MongoDB export JSON (array of captures with nested flowlets).
Labels are derived from capture names:
  - "sensitive_test_*" → sensitive (1)
  - "non_sensitive_test_*" → non_sensitive (0)

Usage:
    python topic_classifier.py data_privacy_project.captures.json \
        --threshold 0.1 \
        --output topic_results.json \
        --model-weights topic_model_weights.pkl
"""
import argparse
import json
import sys
import numpy as np
from pathlib import Path
from typing import Dict, List, Any, Tuple
from collections import defaultdict
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

# Reuse core functions from the existing pipeline
sys.path.insert(0, str(Path(__file__).resolve().parent))
from flowlet_models import (
    bucket_time_gaps,
    build_power_law_blocks,
    build_markov_model,
    compute_sequence_log_likelihood,
    train_and_evaluate_models,
)

LABEL_MAP = {1: "sensitive", 0: "non_sensitive"}


def load_captures(filepath: str) -> List[Dict[str, Any]]:
    """Load MongoDB export: array of capture documents with nested flowlets."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_flowlets(
    captures: List[Dict[str, Any]],
    threshold: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Extract and label flowlets from captures.

    Filters to captures matching the given threshold suffix and whose names
    start with 'sensitive_test' or 'non_sensitive_test'.

    Returns (sensitive_flowlets, non_sensitive_flowlets).
    """
    sensitive = []
    non_sensitive = []

    for cap in captures:
        cap_id = cap.get("_id", "")

        # Only use captures at the requested threshold
        if not cap_id.endswith(f"_{threshold}"):
            continue

        # Determine label from capture name
        if cap_id.startswith("sensitive_test"):
            target = sensitive
        elif cap_id.startswith("non_sensitive_test"):
            target = non_sensitive
        else:
            continue

        for flowlet in cap.get("flowlets", []):
            target.append(flowlet)

    return sensitive, non_sensitive


FEATURE_NAMES = [
    "duration",
    "packet_count",
    "total_bytes",
    "inter_packet_time_mean",
    "inter_packet_time_std",
    "packet_size_mean",
    "packet_size_std",
    "direction_encoded",
]


def extract_ml_features(
    flowlet: Dict[str, Any],
    markov_models: Dict[str, Dict[str, Any]],
    block_mappings: Dict[str, Dict[float, str]],
) -> np.ndarray:
    """Extract feature vector for a flowlet.

    8 features: 7 statistical + 1 direction.
    Markov features are omitted because the MongoDB export does not include
    raw inter_packet_times / packet_sizes arrays.
    """
    features = [
        flowlet.get("duration", 0.0),
        flowlet.get("packet_count", 0),
        flowlet.get("total_bytes", 0),
        flowlet.get("inter_packet_time_mean", 0.0),
        flowlet.get("inter_packet_time_std", 0.0),
        flowlet.get("packet_size_mean", 0.0),
        flowlet.get("packet_size_std", 0.0),
        flowlet.get("direction_encoded", 0),
    ]

    # If raw arrays are available, add Markov log-likelihoods
    inter_packet_times = flowlet.get("inter_packet_times", [])
    packet_sizes = flowlet.get("packet_sizes", [])

    if inter_packet_times and packet_sizes:
        time_gap_seq = bucket_time_gaps(inter_packet_times)

        size_block_seq = []
        if "sensitive" in block_mappings:
            for size in packet_sizes:
                if size in block_mappings["sensitive"]:
                    size_block_seq.append(block_mappings["sensitive"][size])
                else:
                    size_block_seq.append(f"BLOCK_{size:.2f}")

        for class_name in ["sensitive", "non_sensitive"]:
            if class_name in markov_models:
                if "time_gap" in markov_models[class_name]:
                    ll_time = compute_sequence_log_likelihood(
                        time_gap_seq, markov_models[class_name]["time_gap"]
                    )
                    features.append(np.clip(ll_time, -100.0, 0.0))
                else:
                    features.append(-100.0)
                if "size_block" in markov_models[class_name] and size_block_seq:
                    ll_size = compute_sequence_log_likelihood(
                        size_block_seq, markov_models[class_name]["size_block"]
                    )
                    features.append(np.clip(ll_size, -100.0, 0.0))
                else:
                    features.append(-100.0)
            else:
                features.append(-100.0)
                features.append(-100.0)

    return np.array(features)


def prepare_training_data(
    sensitive_flowlets: List[Dict[str, Any]],
    non_sensitive_flowlets: List[Dict[str, Any]],
) -> Tuple[np.ndarray, np.ndarray, List[str], List[str], Dict, Dict]:
    """Build Markov models and extract features.

    Returns (X, y, groups, provider_labels, markov_models, block_mappings).
    """
    print(f"Sensitive flowlets: {len(sensitive_flowlets)}")
    print(f"Non-sensitive flowlets: {len(non_sensitive_flowlets)}")

    # Build block mappings per class
    block_mappings = {}
    for class_name, flowlets in [
        ("sensitive", sensitive_flowlets),
        ("non_sensitive", non_sensitive_flowlets),
    ]:
        all_sizes = []
        for f in flowlets:
            all_sizes.extend(f.get("packet_sizes", []))
        if all_sizes:
            blocks, mapping = build_power_law_blocks(all_sizes, coverage=0.9)
            block_mappings[class_name] = mapping
            print(f"{class_name}: {len(blocks)} packet size blocks")

    # Build Markov models per class
    markov_models = {}
    for class_name, flowlets in [
        ("sensitive", sensitive_flowlets),
        ("non_sensitive", non_sensitive_flowlets),
    ]:
        time_gap_sequences = []
        size_block_sequences = []

        for f in flowlets:
            ipt = f.get("inter_packet_times", [])
            ps = f.get("packet_sizes", [])
            if ipt:
                time_gap_sequences.append(bucket_time_gaps(ipt))
            if ps and class_name in block_mappings:
                size_block_sequences.append(
                    [block_mappings[class_name].get(s, f"BLOCK_{s:.2f}") for s in ps]
                )

        markov_models[class_name] = {
            "time_gap": build_markov_model(time_gap_sequences),
            "size_block": build_markov_model(size_block_sequences),
        }
        print(f"{class_name}: Built Markov models")

    # Extract features
    X_list = []
    y_list = []
    groups = []
    provider_labels = []

    for label, flowlets in [(1, sensitive_flowlets), (0, non_sensitive_flowlets)]:
        for f in flowlets:
            feature_vec = extract_ml_features(f, markov_models, block_mappings)
            X_list.append(feature_vec)
            y_list.append(label)

            flow_key = f.get("flow_key", {})
            group_id = (
                f"{flow_key.get('src_ip', '')}_{flow_key.get('src_port', '')}_"
                f"{flow_key.get('dst_ip', '')}_{flow_key.get('dst_port', '')}_"
                f"{flow_key.get('protocol', '')}"
            )
            groups.append(group_id)
            provider_labels.append(f.get("llm_name", "UNKNOWN"))

    X = np.array(X_list)
    y = np.array(y_list)

    return X, y, groups, provider_labels, markov_models, block_mappings


def evaluate_per_provider(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    providers: List[str],
) -> Dict[str, Any]:
    """Compute metrics broken down by LLM provider."""
    results = {}
    unique_providers = sorted(set(providers))
    providers_arr = np.array(providers)

    for provider in unique_providers:
        mask = providers_arr == provider
        if mask.sum() == 0:
            continue
        yt = y_true[mask]
        yp = y_pred[mask]

        # Skip if only one class present in this slice
        if len(np.unique(yt)) < 2:
            results[provider] = {
                "count": int(mask.sum()),
                "sensitive_count": int((yt == 1).sum()),
                "non_sensitive_count": int((yt == 0).sum()),
                "note": "only one class present in test split",
            }
            continue

        results[provider] = {
            "count": int(mask.sum()),
            "sensitive_count": int((yt == 1).sum()),
            "non_sensitive_count": int((yt == 0).sum()),
            "accuracy": float(accuracy_score(yt, yp)),
            "precision": float(precision_score(yt, yp, zero_division=0)),
            "recall": float(recall_score(yt, yp, zero_division=0)),
            "f1": float(f1_score(yt, yp, zero_division=0)),
            "confusion_matrix": confusion_matrix(yt, yp).tolist(),
        }

    return results


def main():
    p = argparse.ArgumentParser(
        description="Train sensitive-topic classifiers on LLM traffic metadata"
    )
    p.add_argument("input", help="MongoDB export JSON (captures with nested flowlets)")
    p.add_argument(
        "--threshold",
        default="0.1",
        help="flowlet time threshold to use (default: 0.1)",
    )
    p.add_argument(
        "--output",
        "-o",
        default="topic_results.json",
        help="output JSON for results",
    )
    p.add_argument(
        "--model-weights",
        default="topic_model_weights.pkl",
        help="path to save trained model artifacts",
    )
    p.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="fraction of data for testing (default: 0.2)",
    )
    args = p.parse_args()

    # Load and extract
    print(f"Loading captures from {args.input}...")
    captures = load_captures(args.input)
    print(f"Loaded {len(captures)} capture documents")

    sensitive, non_sensitive = extract_flowlets(captures, args.threshold)
    if not sensitive or not non_sensitive:
        print("ERROR: No sensitive or non-sensitive flowlets found.")
        print(f"  Sensitive: {len(sensitive)}, Non-sensitive: {len(non_sensitive)}")
        print("  Check that capture names match 'sensitive_test_*' / 'non_sensitive_test_*'")
        sys.exit(1)

    # Prepare data
    print("\nPreparing training data...")
    X, y, groups, providers, markov_models, block_mappings = prepare_training_data(
        sensitive, non_sensitive
    )
    print(f"Feature matrix shape: {X.shape}")
    print(f"Class distribution: {np.bincount(y)}  (0=non_sensitive, 1=sensitive)")

    # Provider distribution
    provider_counts = defaultdict(lambda: [0, 0])
    for prov, label in zip(providers, y):
        provider_counts[prov][label] += 1
    print("\nPer-provider distribution:")
    for prov, counts in sorted(provider_counts.items()):
        print(f"  {prov}: {counts[0]} non_sensitive, {counts[1]} sensitive")

    # Split
    print("\nSplitting data by flows...")
    gss = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups))

    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    providers_test = [providers[i] for i in test_idx]

    print(f"Train set: {len(X_train)} flowlets")
    print(f"Test set: {len(X_test)} flowlets")
    print(f"Train class distribution: {np.bincount(y_train)}")
    print(f"Test class distribution: {np.bincount(y_test)}")

    # Train
    print("\nTraining models...")
    results, trained_models, scaler = train_and_evaluate_models(
        X_train, X_test, y_train, y_test
    )

    # Fix class names in results (train_and_evaluate_models uses "non_llm"/"llm")
    for model_name in results:
        report = results[model_name].get("classification_report", {})
        if "non_llm" in report:
            report["non_sensitive"] = report.pop("non_llm")
        if "llm" in report:
            report["sensitive"] = report.pop("llm")

    # Per-provider breakdown (using best model's predictions)
    print("\nComputing per-provider metrics...")
    provider_results = {}
    for model_name, model in trained_models.items():
        if model_name == "svm":
            X_test_input = scaler.transform(X_test)
        else:
            X_test_input = X_test
        y_pred = model.predict(X_test_input)
        provider_results[model_name] = evaluate_per_provider(
            y_test, y_pred, providers_test
        )

    # Print results
    print("\n" + "=" * 60)
    print("RESULTS: Sensitive Topic Classification")
    print("=" * 60)
    for model_name, metrics in results.items():
        print(f"\n{model_name.upper()}:")
        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall:    {metrics['recall']:.4f}")
        print(f"  F1 Score:  {metrics['f1']:.4f}")
        cm = metrics["confusion_matrix"]
        print(f"  Confusion Matrix:")
        print(f"    [[TN={cm[0][0]}, FP={cm[0][1]}],")
        print(f"     [FN={cm[1][0]}, TP={cm[1][1]}]]")

        if model_name in provider_results:
            print(f"  Per-provider:")
            for prov, pmetrics in sorted(provider_results[model_name].items()):
                if "accuracy" in pmetrics:
                    print(
                        f"    {prov}: acc={pmetrics['accuracy']:.3f} "
                        f"prec={pmetrics['precision']:.3f} "
                        f"rec={pmetrics['recall']:.3f} "
                        f"f1={pmetrics['f1']:.3f} "
                        f"(n={pmetrics['count']})"
                    )
                else:
                    print(
                        f"    {prov}: {pmetrics.get('note', 'n/a')} "
                        f"(n={pmetrics['count']})"
                    )

    # Save results
    output_data = {
        "dataset_info": {
            "total_flowlets": len(sensitive) + len(non_sensitive),
            "sensitive_count": len(sensitive),
            "non_sensitive_count": len(non_sensitive),
            "threshold": args.threshold,
            "train_size": len(X_train),
            "test_size": len(X_test),
            "feature_dim": X.shape[1],
            "train_class_distribution": np.bincount(y_train).tolist(),
            "test_class_distribution": np.bincount(y_test).tolist(),
        },
        "models": results,
        "per_provider": provider_results,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)
    print(f"\nResults saved to {args.output}")

    # Save model artifacts
    import joblib

    model_artifacts = {
        "models": trained_models,
        "scaler": scaler,
        "markov_models": markov_models,
        "block_mappings": block_mappings,
        "feature_dim": int(X.shape[1]),
        "labels": {"non_sensitive": 0, "sensitive": 1},
        "training_metadata": {
            "input_file": str(args.input),
            "threshold": args.threshold,
            "test_size": args.test_size,
            "train_size": len(X_train),
            "test_size_count": len(X_test),
        },
    }
    joblib.dump(model_artifacts, args.model_weights)
    print(f"Model artifacts saved to {args.model_weights}")


if __name__ == "__main__":
    main()
