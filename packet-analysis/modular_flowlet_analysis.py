#!/usr/bin/env python3
"""modular_flowlet_analysis.py

Modular exploratory analysis for LLM vs non-LLM flowlets with configurable provider and direction.

This script generates correlation matrices, feature importance, and distribution comparisons
for any specified LLM provider (chatgpt, claude, gemini) and direction (incoming, outgoing, both).

Examples:
    python packet-analysis/modular_flowlet_analysis.py flowlet_features.json \
        --llm chatgpt --direction incoming

    python packet-analysis/modular_flowlet_analysis.py flowlet_features.json \
        --llm gemini --direction both --output analysis_results.json
"""

import argparse
import json
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from typing import Dict, List, Any, Tuple
from scipy import stats
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import xgboost as xgb


def load_flowlet_features(filepath: str) -> List[Dict[str, Any]]:
    """Load flowlet features from JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def matches_direction(flowlet: Dict[str, Any], direction: str) -> bool:
    """Check whether a flowlet matches the configured direction filter."""
    if direction == "both":
        return True

    outgoing = bool(flowlet.get("outgoing", False))
    if direction == "outgoing":
        return outgoing
    return not outgoing


def filter_llm_for_analysis(
    features: List[Dict[str, Any]],
    llm_name: str,
    direction: str,
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Filter to LLM (matched by llm_name or source_file) vs non-LLM flowlets by direction.
    
    Args:
        features: List of flowlet dictionaries
        llm_name: LLM provider name (chatgpt, claude, gemini)
        direction: Direction filter (incoming, outgoing, both)
    
    Returns:
        Tuple of (filtered flowlets, filter statistics)
    """
    filtered: List[Dict[str, Any]] = []
    stats_dict = {
        "kept_llm": 0,
        "kept_non_llm": 0,
        "skipped_llm_direction": 0,
        "skipped_llm_name": 0,
        "skipped_other": 0,
    }

    for flowlet in features:
        traffic_class = flowlet.get("traffic_class", "")

        # Always keep non-LLM flowlets regardless of direction
        if traffic_class == "non_llm":
            filtered.append(flowlet)
            stats_dict["kept_non_llm"] += 1
            continue

        # Skip if not LLM traffic
        if traffic_class != "llm":
            stats_dict["skipped_other"] += 1
            continue

        # Check if LLM name matches
        source = str(flowlet.get("source_file", "")).lower()
        llm_field = str(flowlet.get("llm_name", "")).lower()
        
        # Match if source_file contains llm_name or llm_name field matches
        name_matches = (llm_name.lower() in source) or (llm_name.lower() == llm_field)
        if not name_matches:
            stats_dict["skipped_llm_name"] += 1
            continue

        # Check direction
        if not matches_direction(flowlet, direction):
            stats_dict["skipped_llm_direction"] += 1
            continue

        filtered.append(flowlet)
        stats_dict["kept_llm"] += 1

    return filtered, stats_dict


def extract_statistical_features(
    features: List[Dict[str, Any]],
) -> Tuple[np.ndarray, np.ndarray, List[str], List[str]]:
    """Extract statistical features for analysis.
    
    Returns:
        X: Feature matrix
        y: Labels (0=non_llm, 1=llm)
        feature_names: List of feature names
        groups: Flow identifiers
    """
    feature_names = [
        "duration",
        "packet_count",
        "total_bytes",
        "inter_packet_time_mean",
        "inter_packet_time_std",
        "packet_size_mean",
        "packet_size_std",
    ]

    X_list = []
    y_list = []
    groups = []

    for f in features:
        feature_vec = [
            f.get("duration", 0.0),
            f.get("packet_count", 0),
            f.get("total_bytes", 0),
            f.get("inter_packet_time_mean", 0.0),
            f.get("inter_packet_time_std", 0.0),
            f.get("packet_size_mean", 0.0),
            f.get("packet_size_std", 0.0),
        ]

        X_list.append(feature_vec)
        y_list.append(1 if f["traffic_class"] == "llm" else 0)

        # Create group identifier
        flow_key = f.get("flow_key", {})
        group_id = f"{flow_key.get('src_ip', '')}_{flow_key.get('src_port', '')}_{flow_key.get('dst_ip', '')}_{flow_key.get('dst_port', '')}_{flow_key.get('protocol', '')}"
        groups.append(group_id)

    return np.array(X_list), np.array(y_list), feature_names, groups


def compute_correlation_matrix(
    X: np.ndarray, y: np.ndarray, feature_names: List[str]
) -> Dict[str, Any]:
    """Compute correlation matrix including target variable."""
    X_with_target = np.column_stack([X, y])
    feature_names_with_target = feature_names + ["is_llm"]

    corr_matrix = np.corrcoef(X_with_target.T)

    corr_dict = {}
    for i, name1 in enumerate(feature_names_with_target):
        corr_dict[name1] = {}
        for j, name2 in enumerate(feature_names_with_target):
            corr_dict[name1][name2] = float(corr_matrix[i, j])

    return {
        "correlation_matrix": corr_dict,
        "feature_names": feature_names_with_target,
        "shape": list(corr_matrix.shape),
    }


def compute_feature_importance_rf(
    X_train: np.ndarray, y_train: np.ndarray, feature_names: List[str]
) -> Dict[str, float]:
    """Compute feature importance using Random Forest."""
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)

    importance_dict = {}
    for name, importance in zip(feature_names, rf.feature_importances_):
        importance_dict[name] = float(importance)

    return importance_dict


def compute_feature_importance_xgb(
    X_train: np.ndarray, y_train: np.ndarray, feature_names: List[str]
) -> Dict[str, float]:
    """Compute feature importance using XGBoost."""
    xgb_model = xgb.XGBClassifier(
        n_estimators=100,
        random_state=42,
        eval_metric="logloss",
        use_label_encoder=False,
    )
    xgb_model.fit(X_train, y_train)

    importance_dict = {}
    for name, importance in zip(feature_names, xgb_model.feature_importances_):
        importance_dict[name] = float(importance)

    return importance_dict


def compute_statistical_tests(
    X: np.ndarray, y: np.ndarray, feature_names: List[str]
) -> Dict[str, Any]:
    """Perform statistical tests to compare LLM vs non-LLM for each feature."""
    llm_mask = y == 1
    non_llm_mask = y == 0

    results = {}

    for i, name in enumerate(feature_names):
        llm_values = X[llm_mask, i]
        non_llm_values = X[non_llm_mask, i]

        statistic, p_value = stats.mannwhitneyu(
            llm_values, non_llm_values, alternative="two-sided"
        )

        mean_diff = np.mean(llm_values) - np.mean(non_llm_values)
        pooled_std = np.sqrt((np.std(llm_values) ** 2 + np.std(non_llm_values) ** 2) / 2)
        cohens_d = mean_diff / pooled_std if pooled_std > 0 else 0

        results[name] = {
            "llm_mean": float(np.mean(llm_values)),
            "llm_std": float(np.std(llm_values)),
            "llm_median": float(np.median(llm_values)),
            "non_llm_mean": float(np.mean(non_llm_values)),
            "non_llm_std": float(np.std(non_llm_values)),
            "non_llm_median": float(np.median(non_llm_values)),
            "mann_whitney_u": float(statistic),
            "p_value": float(p_value),
            "cohens_d": float(cohens_d),
            "significant": bool(p_value < 0.05),
        }

    return results


def plot_correlation_heatmap(corr_data: Dict[str, Any], output_dir: Path):
    """Generate correlation heatmap visualization."""
    feature_names = corr_data["feature_names"]
    n = len(feature_names)

    corr_matrix = np.zeros((n, n))
    for i, name1 in enumerate(feature_names):
        for j, name2 in enumerate(feature_names):
            corr_matrix[i, j] = corr_data["correlation_matrix"][name1][name2]

    plt.figure(figsize=(12, 10))
    sns.heatmap(
        corr_matrix,
        annot=True,
        fmt=".2f",
        cmap="coolwarm",
        center=0,
        xticklabels=feature_names,
        yticklabels=feature_names,
        cbar_kws={"label": "Correlation"},
        vmin=-1,
        vmax=1,
    )
    plt.title("Feature Correlation Matrix (including target 'is_llm')", fontsize=14, pad=20)
    plt.tight_layout()
    plt.savefig(output_dir / "correlation_heatmap.png", dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved correlation heatmap to {output_dir / 'correlation_heatmap.png'}")


def plot_feature_importance(importance_data: Dict[str, Dict[str, float]], output_dir: Path):
    """Generate feature importance bar plots."""
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    for idx, (model_name, importance_dict) in enumerate(importance_data.items()):
        sorted_features = sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)
        names = [x[0] for x in sorted_features]
        values = [x[1] for x in sorted_features]

        axes[idx].barh(names, values, color="steelblue")
        axes[idx].set_xlabel("Importance", fontsize=12)
        axes[idx].set_title(f"{model_name} Feature Importance", fontsize=13)
        axes[idx].invert_yaxis()

        for i, v in enumerate(values):
            axes[idx].text(v, i, f" {v:.3f}", va="center", fontsize=10)

    plt.tight_layout()
    plt.savefig(output_dir / "feature_importance.png", dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved feature importance plot to {output_dir / 'feature_importance.png'}")


def plot_feature_distributions(X: np.ndarray, y: np.ndarray, feature_names: List[str], output_dir: Path):
    """Generate distribution comparison plots for each feature."""
    llm_mask = y == 1
    non_llm_mask = y == 0

    n_features = len(feature_names)
    n_cols = 3
    n_rows = (n_features + n_cols - 1) // n_cols

    fig, axes = plt.subplots(n_rows, n_cols, figsize=(15, 4 * n_rows))
    axes = axes.flatten() if n_features > 1 else [axes]

    for i, name in enumerate(feature_names):
        llm_values = X[llm_mask, i]
        non_llm_values = X[non_llm_mask, i]

        data_to_plot = [non_llm_values, llm_values]
        parts = axes[i].violinplot(data_to_plot, positions=[0, 1], showmeans=True, showmedians=True)

        for pc, color in zip(parts["bodies"], ["lightblue", "lightcoral"]):
            pc.set_facecolor(color)
            pc.set_alpha(0.7)

        axes[i].set_xticks([0, 1])
        axes[i].set_xticklabels(["Non-LLM", "LLM"])
        axes[i].set_ylabel("Value", fontsize=10)
        axes[i].set_title(name.replace("_", " ").title(), fontsize=11)
        axes[i].grid(axis="y", alpha=0.3)

    for i in range(n_features, len(axes)):
        axes[i].axis("off")

    plt.suptitle("Feature Distributions: LLM vs Non-LLM", fontsize=14, y=1.00)
    plt.tight_layout()
    plt.savefig(output_dir / "feature_distributions.png", dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved feature distributions plot to {output_dir / 'feature_distributions.png'}")


def plot_target_correlations(corr_data: Dict[str, Any], output_dir: Path):
    """Generate bar plot showing correlation of each feature with target."""
    feature_names = corr_data["feature_names"][:-1]  # Exclude 'is_llm' itself
    correlations = []

    for name in feature_names:
        corr = corr_data["correlation_matrix"][name]["is_llm"]
        correlations.append(corr)

    sorted_pairs = sorted(
        zip(feature_names, correlations), key=lambda x: abs(x[1]), reverse=True
    )
    names, corrs = zip(*sorted_pairs) if sorted_pairs else ([], [])

    plt.figure(figsize=(10, 6))
    bars = plt.bar(names, corrs, color="teal")
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("Correlation with is_llm")
    plt.title("Feature Correlation with LLM Target")
    plt.axhline(0, color="black", linewidth=0.8)

    for bar, val in zip(bars, corrs):
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            val,
            f"{val:.2f}",
            ha="center",
            va="bottom" if val > 0 else "top",
        )

    plt.tight_layout()
    plt.savefig(output_dir / "target_correlations.png", dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved target correlation bar plot to {output_dir / 'target_correlations.png'}")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Modular exploratory analysis on LLM vs non-LLM flowlets"
    )
    parser.add_argument("input", help="JSON file with flowlet features")
    parser.add_argument(
        "--llm",
        required=True,
        choices=["chatgpt", "claude", "gemini"],
        help="LLM provider name",
    )
    parser.add_argument(
        "--direction",
        choices=["incoming", "outgoing", "both"],
        default="incoming",
        help="Direction filter (non-LLM flowlets always included)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="output directory for analysis results (default: packet-analysis/{llm}/{direction}_analysis)",
    )
    args = parser.parse_args(argv)

    # Determine output directory
    if args.output is None:
        output_dir = Path("packet-analysis") / args.llm / f"{args.direction}_analysis"
    else:
        output_dir = Path(args.output)

    print(f"Loading features from {args.input}...")
    features = load_flowlet_features(args.input)
    print(f"Loaded {len(features)} flowlets")

    print(f"Applying filter: llm={args.llm}, direction={args.direction}")
    filtered, filter_stats = filter_llm_for_analysis(
        features=features,
        llm_name=args.llm,
        direction=args.direction,
    )

    print(
        f"Filter stats: "
        f"kept_llm={filter_stats['kept_llm']}, "
        f"kept_non_llm={filter_stats['kept_non_llm']}, "
        f"skipped_llm_name={filter_stats['skipped_llm_name']}, "
        f"skipped_llm_direction={filter_stats['skipped_llm_direction']}, "
        f"skipped_other={filter_stats['skipped_other']}"
    )
    print(f"Filtered to {len(filtered)} relevant flowlets")

    if len(filtered) == 0:
        print("ERROR: No flowlets remain after filtering. Exiting.")
        return

    X, y, feature_names, groups = extract_statistical_features(filtered)

    if len(np.unique(y)) < 2:
        print("WARNING: Only one class present after filtering. Analysis may be limited.")

    corr_data = compute_correlation_matrix(X, y, feature_names)
    importance_rf = compute_feature_importance_rf(X, y, feature_names)
    importance_xgb = compute_feature_importance_xgb(X, y, feature_names)
    stats_results = compute_statistical_tests(X, y, feature_names)

    output_dir.mkdir(parents=True, exist_ok=True)

    plot_correlation_heatmap(corr_data, output_dir)
    plot_target_correlations(corr_data, output_dir)
    plot_feature_importance({"RF": importance_rf, "XGB": importance_xgb}, output_dir)
    plot_feature_distributions(X, y, feature_names, output_dir)

    summary = {
        "llm": args.llm,
        "direction": args.direction,
        "filter_stats": filter_stats,
        "dataset_info": {
            "total_flowlets": len(filtered),
            "llm_count": filter_stats["kept_llm"],
            "non_llm_count": filter_stats["kept_non_llm"],
            "feature_dim": X.shape[1],
        },
        "correlation": corr_data,
        "feature_importance": {"rf": importance_rf, "xgb": importance_xgb},
        "statistical_tests": stats_results,
    }

    with open(output_dir / "analysis_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\nAnalysis complete. Output written to {output_dir}")


if __name__ == "__main__":
    main()
