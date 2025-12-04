#!/usr/bin/env python3
"""flowlet_analysis_gemini.py

Analyze Gemini flowlet features to understand which are most important for classification.
Generates correlation matrices, feature importance, and distribution comparisons.

Usage: python3 flowlet_analysis_gemini.py <features.json> --output analysis_results_gemini.json
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


def filter_gemini_only(features: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filter to only Gemini (llm) vs non-LLM flowlets."""
    filtered = []
    for f in features:
        source = f.get("source_file", "")
        traffic_class = f.get("traffic_class", "")
        
        if "gemini" in source.lower() or traffic_class == "non_llm":
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
        
        # Mann-Whitney U test (non-parametric)
        statistic, p_value = stats.mannwhitneyu(llm_values, non_llm_values, alternative='two-sided')
        
        # Effect size (Cohen's d)
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
    
    # Reconstruct matrix from dict
    corr_matrix = np.zeros((n, n))
    for i, name1 in enumerate(feature_names):
        for j, name2 in enumerate(feature_names):
            corr_matrix[i, j] = corr_data["correlation_matrix"][name1][name2]
    
    # Create heatmap
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
        # Sort by importance
        sorted_features = sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)
        names = [x[0] for x in sorted_features]
        values = [x[1] for x in sorted_features]
        
        axes[idx].barh(names, values, color='steelblue')
        axes[idx].set_xlabel('Importance', fontsize=12)
        axes[idx].set_title(f'{model_name} Feature Importance', fontsize=13)
        axes[idx].invert_yaxis()
        
        # Add value labels
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
        
        # Create violin plot
        data_to_plot = [non_llm_values, llm_values]
        parts = axes[i].violinplot(data_to_plot, positions=[0, 1], showmeans=True, showmedians=True)
        
        # Color the violins
        for pc, color in zip(parts['bodies'], ['lightblue', 'lightcoral']):
            pc.set_facecolor(color)
            pc.set_alpha(0.7)
        
        axes[i].set_xticks([0, 1])
        axes[i].set_xticklabels(['Non-LLM', 'LLM'])
        axes[i].set_ylabel('Value', fontsize=10)
        axes[i].set_title(name.replace('_', ' ').title(), fontsize=11)
        axes[i].grid(axis='y', alpha=0.3)
    
    # Hide unused subplots
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
    sorted_indices = np.argsort(np.abs(correlations))[::-1]
    sorted_names = [feature_names[i] for i in sorted_indices]
    sorted_corrs = [correlations[i] for i in sorted_indices]
    
    # Create bar plot
    plt.figure(figsize=(10, 6))
    colors = ['red' if c < 0 else 'green' for c in sorted_corrs]
    plt.barh(sorted_names, sorted_corrs, color=colors, alpha=0.7)
    plt.xlabel('Correlation with LLM Label', fontsize=12)
    plt.title('Feature Correlation with Target (is_llm)', fontsize=14)
    plt.axvline(x=0, color='black', linestyle='-', linewidth=0.8)
    plt.grid(axis='x', alpha=0.3)
    
    # Add value labels
    for i, v in enumerate(sorted_corrs):
        plt.text(v, i, f' {v:.3f}', va='center', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(output_dir / "target_correlations.png", dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved target correlations plot to {output_dir / 'target_correlations.png'}")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Analyze Gemini flowlet features for LLM classification"
    )
    p.add_argument("input", help="JSON file with flowlet features")
    p.add_argument(
        "--output",
        "-o",
        default="analysis_results_gemini.json",
        help="output JSON file for analysis results",
    )
    p.add_argument(
        "--output-dir",
        default="analysis_plots_gemini",
        help="directory for output plots (default: analysis_plots_gemini)",
    )
    p.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="fraction of data for testing (default: 0.2)",
    )
    args = p.parse_args(argv)
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    # Load features
    print(f"Loading features from {args.input}...")
    features = load_flowlet_features(args.input)
    print(f"Loaded {len(features)} flowlets")
    
    # Filter to Gemini only
    features = filter_gemini_only(features)
    print(f"Filtered to {len(features)} Gemini/non-LLM flowlets")
    
    # Extract statistical features
    print("Extracting statistical features...")
    X, y, feature_names, groups = extract_statistical_features(features)
    print(f"Feature matrix shape: {X.shape}")
    print(f"Features: {feature_names}")
    
    # Split data
    print("Splitting data by flows...")
    gss = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups))
    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    
    # Compute correlation matrix
    print("\nComputing correlation matrix...")
    corr_data = compute_correlation_matrix(X, y, feature_names)
    
    # Compute feature importance
    print("Computing feature importance (Random Forest)...")
    rf_importance = compute_feature_importance_rf(X_train, y_train, feature_names)
    
    print("Computing feature importance (XGBoost)...")
    xgb_importance = compute_feature_importance_xgb(X_train, y_train, feature_names)
    
    # Statistical tests
    print("Performing statistical tests...")
    stat_tests = compute_statistical_tests(X, y, feature_names)
    
    # Generate plots
    print("\nGenerating visualizations...")
    plot_correlation_heatmap(corr_data, output_dir)
    plot_feature_importance(
        {"Random Forest": rf_importance, "XGBoost": xgb_importance},
        output_dir
    )
    plot_feature_distributions(X, y, feature_names, output_dir)
    plot_target_correlations(corr_data, output_dir)
    
    # Compile results
    results = {
        "dataset_info": {
            "total_flowlets": len(features),
            "llm_flowlets": int(np.sum(y)),
            "non_llm_flowlets": int(len(y) - np.sum(y)),
            "feature_names": feature_names,
        },
        "correlation_analysis": corr_data,
        "feature_importance": {
            "random_forest": rf_importance,
            "xgboost": xgb_importance,
        },
        "statistical_tests": stat_tests,
        "summary": {
            "most_correlated_features": sorted(
                [(name, abs(corr_data["correlation_matrix"][name]["is_llm"])) 
                 for name in feature_names],
                key=lambda x: x[1],
                reverse=True
            ),
            "most_important_features_rf": sorted(
                rf_importance.items(),
                key=lambda x: x[1],
                reverse=True
            ),
            "most_important_features_xgb": sorted(
                xgb_importance.items(),
                key=lambda x: x[1],
                reverse=True
            ),
            "significant_features": [
                name for name, data in stat_tests.items() if data["significant"]
            ],
        },
    }
    
    # Save results
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n{'='*60}")
    print("ANALYSIS SUMMARY")
    print(f"{'='*60}")
    
    print("\nMost Correlated Features with LLM Label:")
    for name, corr in results["summary"]["most_correlated_features"][:5]:
        actual_corr = corr_data["correlation_matrix"][name]["is_llm"]
        print(f"  {name:30s}: {actual_corr:+.4f}")
    
    print("\nMost Important Features (Random Forest):")
    for name, importance in results["summary"]["most_important_features_rf"][:5]:
        print(f"  {name:30s}: {importance:.4f}")
    
    print("\nMost Important Features (XGBoost):")
    for name, importance in results["summary"]["most_important_features_xgb"][:5]:
        print(f"  {name:30s}: {importance:.4f}")
    
    print(f"\nStatistically Significant Features (p < 0.05): {len(results['summary']['significant_features'])}/{len(feature_names)}")
    for name in results["summary"]["significant_features"]:
        test_data = stat_tests[name]
        print(f"  {name:30s}: p={test_data['p_value']:.2e}, Cohen's d={test_data['cohens_d']:+.3f}")
    
    print(f"\nResults saved to {args.output}")
    print(f"Plots saved to {output_dir}/")


if __name__ == "__main__":
    main()
