#!/usr/bin/env python3
"""incoming_analysis.py

Analyze flowlet features for incoming ChatGPT vs non-LLM flowlets.
Generates correlation matrices, feature importance, and distribution comparisons.

Only chatgpt flowlets with outgoing=False are treated as LLM examples; non-LLM
flowlets are included regardless of direction.  Outgoing ChatGPT flowlets are
excluded from analysis.

Usage: python3 incoming_analysis.py <features.json> --output analysis_results.json
"""
import argparse
import json
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from typing import Dict, List, Any, Tuple
from collections import defaultdict
from scipy import stats
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GroupShuffleSplit
import xgboost as xgb


def load_flowlet_features(filepath: str) -> List[Dict[str, Any]]:
    """Load flowlet features from JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def filter_chatgpt_incoming(features: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filter to only incoming ChatGPT (llm) vs non-LLM flowlets.

    - ChatGPT flowlets must have outgoing == False to be included.
    - Non-LLM flowlets are always included.
    """
    filtered = []
    for f in features:
        source = f.get("source_file", "")
        traffic_class = f.get("traffic_class", "")
        outgoing = f.get("outgoing", False)

        if traffic_class == "non_llm":
            filtered.append(f)
        else:
            if "chatgpt" in source.lower() and not outgoing:
                filtered.append(f)
    return filtered


def extract_statistical_features(features: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray, List[str], List[str]]:
    """Extract only statistical features (no Markov features) for analysis.
    
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


def compute_correlation_matrix(X: np.ndarray, y: np.ndarray, feature_names: List[str]) -> Dict[str, Any]:
    """Compute correlation matrix including target variable."""
    # Add target to feature matrix
    X_with_target = np.column_stack([X, y])
    feature_names_with_target = feature_names + ["is_llm"]
    
    # Compute correlation matrix
    corr_matrix = np.corrcoef(X_with_target.T)
    
    # Convert to dict for JSON serialization
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
    X_train: np.ndarray, 
    y_train: np.ndarray, 
    feature_names: List[str]
) -> Dict[str, float]:
    """Compute feature importance using Random Forest."""
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    
    importance_dict = {}
    for name, importance in zip(feature_names, rf.feature_importances_):
        importance_dict[name] = float(importance)
    
    return importance_dict


def compute_feature_importance_xgb(
    X_train: np.ndarray, 
    y_train: np.ndarray, 
    feature_names: List[str]
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
    X: np.ndarray, 
    y: np.ndarray, 
    feature_names: List[str]
) -> Dict[str, Any]:
    """Perform statistical tests to compare LLM vs non-LLM for each feature."""
    llm_mask = y == 1
    non_llm_mask = y == 0
    
    results = {}
    
    for i, name in enumerate(feature_names):
        llm_values = X[llm_mask, i]
        non_llm_values = X[non_llm_mask, i]
        
        statistic, p_value = stats.mannwhitneyu(llm_values, non_llm_values, alternative='two-sided')
        
        mean_diff = np.mean(llm_values) - np.mean(non_llm_values)
        pooled_std = np.sqrt((np.std(llm_values)**2 + np.std(non_llm_values)**2) / 2)
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
        
        axes[idx].barh(names, values, color='steelblue')
        axes[idx].set_xlabel('Importance', fontsize=12)
        axes[idx].set_title(f'{model_name} Feature Importance', fontsize=13)
        axes[idx].invert_yaxis()
        
        for i, v in enumerate(values):
            axes[idx].text(v, i, f' {v:.3f}', va='center', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(output_dir / "feature_importance.png", dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved feature importance plot to {output_dir / 'feature_importance.png'}")


def plot_feature_distributions(
    X: np.ndarray, 
    y: np.ndarray, 
    feature_names: List[str], 
    output_dir: Path
):
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
        
        for pc, color in zip(parts['bodies'], ['lightblue', 'lightcoral']):
            pc.set_facecolor(color)
            pc.set_alpha(0.7)
        
        axes[i].set_xticks([0, 1])
        axes[i].set_xticklabels(['Non-LLM', 'LLM'])
        axes[i].set_ylabel('Value', fontsize=10)
        axes[i].set_title(name.replace('_', ' ').title(), fontsize=11)
        axes[i].grid(axis='y', alpha=0.3)
    
    for i in range(n_features, len(axes)):
        axes[i].axis('off')
    
    plt.suptitle('Feature Distributions: LLM vs Non-LLM', fontsize=14, y=1.00)
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
    
    # Sort by absolute correlation
    sorted_pairs = sorted(zip(feature_names, correlations), key=lambda x: abs(x[1]), reverse=True)
    names, corrs = zip(*sorted_pairs) if sorted_pairs else ([],[])
    
    plt.figure(figsize=(10, 6))
    bars = plt.bar(names, corrs, color='teal')
    plt.xticks(rotation=45, ha='right')
    plt.ylabel('Correlation with is_llm')
    plt.title('Feature Correlation with LLM Target')
    plt.axhline(0, color='black', linewidth=0.8)
    
    for bar, val in zip(bars, corrs):
        plt.text(bar.get_x() + bar.get_width()/2, val, f'{val:.2f}', ha='center', va='bottom' if val>0 else 'top')
    
    plt.tight_layout()
    plt.savefig(output_dir / "target_correlations.png", dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved target correlation bar plot to {output_dir / 'target_correlations.png'}")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Perform exploratory analysis on incoming LLM vs non-LLM flowlets"
    )
    p.add_argument("input", help="JSON file with flowlet features")
    p.add_argument(
        "--output",
        "-o",
        default="analysis_results.json",
        help="directory for output figures and summaries",
    )
    args = p.parse_args(argv)

    print(f"Loading features from {args.input}...")
    features = load_flowlet_features(args.input)
    print(f"Loaded {len(features)} flowlets")

    features = filter_chatgpt_incoming(features)
    print(f"Filtered to {len(features)} relevant flowlets")

    X, y, feature_names, groups = extract_statistical_features(features)
    
    corr_data = compute_correlation_matrix(X, y, feature_names)
    importance_rf = compute_feature_importance_rf(X, y, feature_names)
    importance_xgb = compute_feature_importance_xgb(X, y, feature_names)
    stats_results = compute_statistical_tests(X, y, feature_names)

    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)

    plot_correlation_heatmap(corr_data, outdir)
    plot_target_correlations(corr_data, outdir)
    plot_feature_importance({"RF": importance_rf, "XGB": importance_xgb}, outdir)
    plot_feature_distributions(X, y, feature_names, outdir)

    summary = {
        "correlation": corr_data,
        "feature_importance": {"rf": importance_rf, "xgb": importance_xgb},
        "statistical_tests": stats_results,
    }

    with open(outdir / "analysis_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"Analysis output written to {outdir}")


if __name__ == "__main__":
    main()
