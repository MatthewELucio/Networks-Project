#!/usr/bin/env python3
"""modular_model_creator.py

Train LLM vs non-LLM classifiers with configurable provider and direction filters.

This script reuses the core feature engineering and model training pipeline from
`flowlet_models.py`, while allowing callers to target:
- specific LLM providers (e.g. chatgpt, claude, gemini)
- incoming only, outgoing only, or both directions

Examples:
    python packet-analysis/modular_model_creator.py flowlet_features.json \
        --llm-sources chatgpt --direction incoming

    python packet-analysis/modular_model_creator.py captures/chatgpt_ipv4 \
        --llm-sources chatgpt --direction both

    python packet-analysis/modular_model_creator.py flowlet_features.json \
        --llm-sources chatgpt,claude,gemini --direction both \
        --output multi_llm_results.json --model-weights multi_llm_weights.pkl
"""

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
from sklearn.model_selection import GroupShuffleSplit

from flowlet_models import (
    load_flowlet_features,
    prepare_training_data,
    train_and_evaluate_models,
)


def load_features_from_path(input_path: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Load flowlet features from a JSON file or a directory of JSON files."""
    resolved_path = Path(input_path)

    if resolved_path.is_file():
        features = load_flowlet_features(str(resolved_path))
        return features, [str(resolved_path)]

    if resolved_path.is_dir():
        json_files = sorted(path for path in resolved_path.glob("*.json") if path.is_file())
        if not json_files:
            raise ValueError(f"No JSON files found in directory: {resolved_path}")

        merged_features: List[Dict[str, Any]] = []
        loaded_sources: List[str] = []

        for json_file in json_files:
            file_features = load_flowlet_features(str(json_file))
            merged_features.extend(file_features)
            loaded_sources.append(str(json_file))
            print(f"Loaded {len(file_features)} flowlets from {json_file}")

        return merged_features, loaded_sources

    raise ValueError(f"Input path is not a file or directory: {resolved_path}")


def parse_llm_sources(raw_sources: str) -> List[str]:
    """Parse a comma-separated list of provider keywords.

    Returns an empty list when all LLM sources should be accepted.
    """
    raw = raw_sources.strip()
    if raw in {"", "*", "all"}:
        return []

    return [token.strip().lower() for token in raw.split(",") if token.strip()]


def matches_direction(flowlet: Dict[str, Any], direction: str) -> bool:
    """Check whether a flowlet matches the configured direction filter."""
    if direction == "both":
        return True

    outgoing = bool(flowlet.get("outgoing", False))
    if direction == "outgoing":
        return outgoing
    return not outgoing


def filter_llm_and_non_llm(
    features: List[Dict[str, Any]],
    llm_sources: List[str],
    direction: str,
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Filter flowlets for training.

    Rules:
    - Keep all `traffic_class == non_llm` flowlets.
    - For `traffic_class == llm`, keep only entries whose `source_file`
      matches the requested provider list and direction.
    """
    filtered: List[Dict[str, Any]] = []
    stats = {
        "kept_llm": 0,
        "kept_non_llm": 0,
        "skipped_llm_source": 0,
        "skipped_llm_direction": 0,
        "skipped_other": 0,
    }

    for flowlet in features:
        traffic_class = flowlet.get("traffic_class", "")

        if traffic_class == "non_llm":
            filtered.append(flowlet)
            stats["kept_non_llm"] += 1
            continue

        if traffic_class != "llm":
            stats["skipped_other"] += 1
            continue

        source = str(flowlet.get("source_file", "")).lower()
        source_matches = (not llm_sources) or any(token in source for token in llm_sources)
        if not source_matches:
            stats["skipped_llm_source"] += 1
            continue

        if not matches_direction(flowlet, direction):
            stats["skipped_llm_direction"] += 1
            continue

        filtered.append(flowlet)
        stats["kept_llm"] += 1

    return filtered, stats


def print_metrics(results: Dict[str, Any]) -> None:
    """Pretty-print model performance metrics."""
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    for model_name, metrics in results.items():
        print(f"\n{model_name.upper()}:")
        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall:    {metrics['recall']:.4f}")
        print(f"  F1 Score:  {metrics['f1']:.4f}")
        print("  Confusion Matrix:")
        cm = metrics["confusion_matrix"]
        print(f"    [[TN={cm[0][0]}, FP={cm[0][1]}],")
        print(f"     [FN={cm[1][0]}, TP={cm[1][1]}]]")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Train modular LLM vs non-LLM flowlet classifiers"
    )
    parser.add_argument(
        "input",
        help="JSON file with flowlet features, or a directory containing JSON files",
    )
    parser.add_argument(
        "--llm-sources",
        default="chatgpt",
        help=(
            "comma-separated provider keywords matched in source_file "
            "(e.g. chatgpt,claude,gemini). Use '*' or 'all' for any LLM source"
        ),
    )
    parser.add_argument(
        "--direction",
        choices=["incoming", "outgoing", "both"],
        default="incoming",
        help="LLM direction filter (non-LLM flowlets are always included)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="modular_model_results.json",
        help="output JSON file for results",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="fraction of data for testing (default: 0.2)",
    )
    parser.add_argument(
        "--model-weights",
        default="modular_model_weights.pkl",
        help="path to save trained model weights/artifacts (joblib format)",
    )
    args = parser.parse_args(argv)

    llm_sources = parse_llm_sources(args.llm_sources)

    print(f"Loading features from {args.input}...")
    features, input_sources = load_features_from_path(args.input)
    print(f"Loaded {len(features)} flowlets")

    print("Applying modular filter...")
    filtered, filter_stats = filter_llm_and_non_llm(
        features=features,
        llm_sources=llm_sources,
        direction=args.direction,
    )

    selected_sources = "all" if not llm_sources else ", ".join(llm_sources)
    print(f"Selected LLM sources: {selected_sources}")
    print(f"Selected direction: {args.direction}")
    print(
        "Filter stats: "
        f"kept_llm={filter_stats['kept_llm']}, "
        f"kept_non_llm={filter_stats['kept_non_llm']}, "
        f"skipped_llm_source={filter_stats['skipped_llm_source']}, "
        f"skipped_llm_direction={filter_stats['skipped_llm_direction']}, "
        f"skipped_other={filter_stats['skipped_other']}"
    )
    print(f"Filtered to {len(filtered)} flowlets")

    print("Preparing training data...")
    X, y, groups, markov_models, block_mappings = prepare_training_data(filtered)

    if len(np.unique(y)) < 2:
        raise ValueError(
            "Training set contains only one class after filtering. "
            "Adjust --llm-sources or --direction."
        )

    print(f"Feature matrix shape: {X.shape}")
    print(f"Class distribution: {np.bincount(y)}")

    print("Splitting data by flows...")
    gss = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups))

    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]

    print(f"Train set: {len(X_train)} flowlets")
    print(f"Test set: {len(X_test)} flowlets")
    print(f"Train class distribution: {np.bincount(y_train)}")
    print(f"Test class distribution: {np.bincount(y_test)}")

    print("\nTraining models...")
    results, trained_models, scaler = train_and_evaluate_models(
        X_train, X_test, y_train, y_test
    )

    print_metrics(results)

    output_data = {
        "dataset_info": {
            "total_flowlets": len(filtered),
            "train_size": len(X_train),
            "test_size": len(X_test),
            "feature_dim": X.shape[1],
            "train_class_distribution": np.bincount(y_train).tolist(),
            "test_class_distribution": np.bincount(y_test).tolist(),
            "llm_sources": llm_sources if llm_sources else ["all"],
            "direction": args.direction,
            "filter_stats": filter_stats,
            "input_sources": input_sources,
        },
        "models": results,
    }

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(output_data, handle, indent=2)

    print(f"\nResults saved to {args.output}")

    model_weights_path = Path(args.model_weights)
    if model_weights_path.suffix.lower() != ".pkl":
        model_weights_path = model_weights_path.with_suffix(".pkl")
        print(f"Adjusted model artifact path to use .pkl: {model_weights_path}")

    model_artifacts = {
        "models": trained_models,
        "scaler": scaler,
        "markov_models": markov_models,
        "block_mappings": block_mappings,
        "feature_dim": int(X.shape[1]),
        "labels": {"non_llm": 0, "llm": 1},
        "training_metadata": {
            "input_sources": input_sources,
            "test_size": args.test_size,
            "train_size": len(X_train),
            "test_size_count": len(X_test),
            "llm_sources": llm_sources if llm_sources else ["all"],
            "direction": args.direction,
            "filter_stats": filter_stats,
        },
    }

    joblib.dump(model_artifacts, model_weights_path)
    print(f"Model artifacts saved to {model_weights_path}")

    for model_name, model in trained_models.items():
        per_model_path = model_weights_path.with_name(
            f"{model_weights_path.stem}_{model_name}.pkl"
        )
        joblib.dump(model, per_model_path)
        print(f"Saved {model_name} model to {per_model_path}")

    scaler_path = model_weights_path.with_name(f"{model_weights_path.stem}_scaler.pkl")
    joblib.dump(scaler, scaler_path)
    print(f"Saved scaler to {scaler_path}")


if __name__ == "__main__":
    main()
