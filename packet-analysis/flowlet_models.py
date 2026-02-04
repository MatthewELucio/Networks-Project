#!/usr/bin/env python3
"""flowlet_models.py

Train classification models to distinguish LLM vs non-LLM flowlets.
Uses MaMPF-inspired approach with Markov models and traditional ML classifiers.

Usage: python3 flowlet_models.py <features.json> --output results.json
"""
import argparse
import json
import numpy as np
from pathlib import Path
from typing import Dict, List, Any, Tuple
from collections import defaultdict, Counter
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
import joblib
import xgboost as xgb


def load_flowlet_features(filepath: str) -> List[Dict[str, Any]]:
    """Load flowlet features from JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def filter_chatgpt_only(features: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filter to only ChatGPT (llm) vs non-LLM flowlets."""
    filtered = []
    for f in features:
        source = f.get("source_file", "")
        traffic_class = f.get("traffic_class", "")
        
        # Only keep ChatGPT and non-LLM
        if "chatgpt" in source.lower() or traffic_class == "non_llm":
            filtered.append(f)
    
    return filtered


def bucket_time_gaps(time_gaps: List[float]) -> List[str]:
    """Bucket time gaps into discrete states.
    
    Buckets: GAP_0_10ms, GAP_10_100ms, GAP_100ms_1s, GAP_GT_1s
    """
    buckets = []
    for gap in time_gaps:
        gap_ms = gap * 1000  # Convert to milliseconds
        if gap_ms < 10:
            buckets.append("GAP_0_10ms")
        elif gap_ms < 100:
            buckets.append("GAP_10_100ms")
        elif gap_ms < 1000:
            buckets.append("GAP_100ms_1s")
        else:
            buckets.append("GAP_GT_1s")
    return buckets


def build_power_law_blocks(
    values: List[float], coverage: float = 0.9
) -> Tuple[List[float], Dict[float, str]]:
    """Build MaMPF-style blocks from numeric values.
    
    Returns:
        blocks: List of representative block values
        value_to_block: Mapping from value to block name
    """
    if not values:
        return [], {}
    
    # Count frequency of each value
    value_counts = Counter(values)
    total_count = len(values)
    
    # Sort by frequency (descending)
    sorted_values = sorted(value_counts.items(), key=lambda x: x[1], reverse=True)
    
    # Select top values that cover the desired percentage
    cumulative = 0
    blocks = []
    for value, count in sorted_values:
        blocks.append(value)
        cumulative += count
        if cumulative / total_count >= coverage:
            break
    
    # Create mapping from any value to nearest block
    value_to_block = {}
    for val in set(values):
        if val in blocks:
            value_to_block[val] = f"BLOCK_{val:.2f}"
        else:
            # Find nearest block
            nearest = min(blocks, key=lambda b: abs(b - val))
            value_to_block[val] = f"BLOCK_{nearest:.2f}"
    
    return blocks, value_to_block


def build_markov_model(sequences: List[List[str]]) -> Dict[str, Any]:
    """Build first-order Markov chain from sequences.
    
    Returns dict with:
        - transition_counts: state -> next_state -> count
        - transition_probs: state -> next_state -> probability
        - start_probs: state -> probability of being first
        - end_probs: state -> probability of being last
    """
    transition_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    start_counts: Dict[str, int] = defaultdict(int)
    end_counts: Dict[str, int] = defaultdict(int)
    total_sequences = len(sequences)
    
    for seq in sequences:
        if not seq:
            continue
        
        # Start state
        start_counts[seq[0]] += 1
        
        # Transitions
        for i in range(len(seq) - 1):
            transition_counts[seq[i]][seq[i + 1]] += 1
        
        # End state
        end_counts[seq[-1]] += 1
    
    # Convert counts to probabilities
    transition_probs = {}
    for state, next_states in transition_counts.items():
        total = sum(next_states.values())
        transition_probs[state] = {
            next_state: count / total for next_state, count in next_states.items()
        }
    
    start_probs = {
        state: count / total_sequences for state, count in start_counts.items()
    }
    end_probs = {
        state: count / total_sequences for state, count in end_counts.items()
    }
    
    return {
        "transition_counts": dict(transition_counts),
        "transition_probs": transition_probs,
        "start_probs": start_probs,
        "end_probs": end_probs,
    }


def compute_sequence_log_likelihood(
    sequence: List[str], markov_model: Dict[str, Any]
) -> float:
    """Compute log-likelihood of a sequence under a Markov model."""
    if not sequence:
        return -np.inf
    
    transition_probs = markov_model["transition_probs"]
    start_probs = markov_model["start_probs"]
    
    log_prob = 0.0
    
    # Start probability
    if sequence[0] in start_probs:
        log_prob += np.log(start_probs[sequence[0]] + 1e-10)
    else:
        log_prob += np.log(1e-10)  # Smoothing for unseen states
    
    # Transition probabilities
    for i in range(len(sequence) - 1):
        current = sequence[i]
        next_state = sequence[i + 1]
        
        if current in transition_probs and next_state in transition_probs[current]:
            log_prob += np.log(transition_probs[current][next_state] + 1e-10)
        else:
            log_prob += np.log(1e-10)  # Smoothing
    
    # Normalize by sequence length (n-th root trick from MaMPF)
    normalized_log_prob = log_prob / len(sequence) if len(sequence) > 0 else log_prob
    
    return normalized_log_prob


def extract_ml_features(
    flowlet: Dict[str, Any],
    markov_models: Dict[str, Dict[str, Any]],
    block_mappings: Dict[str, Dict[float, str]],
) -> np.ndarray:
    """Extract feature vector for a flowlet.
    
    Combines:
    - Statistical features (mean, std, count, etc.)
    - Direction features (outgoing/incoming for LLM traffic only)
    - Markov model log-likelihoods (MaMPF fingerprint)
    """
    features = []
    
    # Statistical features
    features.append(flowlet.get("duration", 0.0))
    features.append(flowlet.get("packet_count", 0))
    features.append(flowlet.get("total_bytes", 0))
    features.append(flowlet.get("inter_packet_time_mean", 0.0))
    features.append(flowlet.get("inter_packet_time_std", 0.0))
    features.append(flowlet.get("packet_size_mean", 0.0))
    features.append(flowlet.get("packet_size_std", 0.0))
    
    # Direction feature (0 for non-LLM, +1 for outgoing LLM, -1 for incoming LLM)
    features.append(flowlet.get("direction_encoded", 0))
    
    # Build sequences for Markov models
    inter_packet_times = flowlet.get("inter_packet_times", [])
    packet_sizes = flowlet.get("packet_sizes", [])
    
    # Time gap sequence
    time_gap_seq = bucket_time_gaps(inter_packet_times)
    
    # Packet size sequence (using blocks)
    size_block_seq = []
    if "llm" in block_mappings and packet_sizes:
        for size in packet_sizes:
            if size in block_mappings["llm"]:
                size_block_seq.append(block_mappings["llm"][size])
            else:
                # Find nearest block
                size_block_seq.append(f"BLOCK_{size:.2f}")
    
    # Compute log-likelihoods for each class's Markov models
    for class_name in ["llm", "non_llm"]:
        if class_name in markov_models:
            # Time gap model
            if "time_gap" in markov_models[class_name]:
                ll_time = compute_sequence_log_likelihood(
                    time_gap_seq, markov_models[class_name]["time_gap"]
                )
                # Clip to avoid infinity
                ll_time = np.clip(ll_time, -100.0, 0.0)
                features.append(ll_time)
            else:
                features.append(-100.0)
            
            # Size block model
            if "size_block" in markov_models[class_name] and size_block_seq:
                ll_size = compute_sequence_log_likelihood(
                    size_block_seq, markov_models[class_name]["size_block"]
                )
                # Clip to avoid infinity
                ll_size = np.clip(ll_size, -100.0, 0.0)
                features.append(ll_size)
            else:
                features.append(-100.0)
        else:
            features.append(-100.0)
            features.append(-100.0)
    
    return np.array(features)


def prepare_training_data(
    features: List[Dict[str, Any]]
) -> Tuple[np.ndarray, np.ndarray, List[str], Dict[str, Any], Dict[str, Dict[float, str]]]:
    """Prepare training data with Markov models and feature extraction.
    
    Returns:
        X: Feature matrix
        y: Labels (0=non_llm, 1=llm)
        groups: Flow identifiers for group-based splitting
        markov_models: Trained Markov models per class
        block_mappings: Block mappings per class
    """
    # Separate by class
    llm_flowlets = [f for f in features if f["traffic_class"] == "llm"]
    non_llm_flowlets = [f for f in features if f["traffic_class"] == "non_llm"]
    
    print(f"LLM flowlets: {len(llm_flowlets)}")
    print(f"Non-LLM flowlets: {len(non_llm_flowlets)}")
    
    # Build block mappings for packet sizes
    block_mappings = {}
    for class_name, flowlets in [("llm", llm_flowlets), ("non_llm", non_llm_flowlets)]:
        all_sizes = []
        for f in flowlets:
            all_sizes.extend(f.get("packet_sizes", []))
        
        if all_sizes:
            blocks, mapping = build_power_law_blocks(all_sizes, coverage=0.9)
            block_mappings[class_name] = mapping
            print(f"{class_name}: {len(blocks)} packet size blocks")
    
    # Build Markov models for each class
    markov_models = {}
    for class_name, flowlets in [("llm", llm_flowlets), ("non_llm", non_llm_flowlets)]:
        # Time gap sequences
        time_gap_sequences = []
        size_block_sequences = []
        
        for f in flowlets:
            inter_packet_times = f.get("inter_packet_times", [])
            packet_sizes = f.get("packet_sizes", [])
            
            if inter_packet_times:
                time_gap_seq = bucket_time_gaps(inter_packet_times)
                time_gap_sequences.append(time_gap_seq)
            
            if packet_sizes and class_name in block_mappings:
                size_seq = [block_mappings[class_name].get(s, f"BLOCK_{s:.2f}") for s in packet_sizes]
                size_block_sequences.append(size_seq)
        
        markov_models[class_name] = {
            "time_gap": build_markov_model(time_gap_sequences),
            "size_block": build_markov_model(size_block_sequences),
        }
        print(f"{class_name}: Built Markov models")
    
    # Extract features for all flowlets
    X_list = []
    y_list = []
    groups = []
    
    for f in features:
        feature_vec = extract_ml_features(f, markov_models, block_mappings)
        X_list.append(feature_vec)
        y_list.append(1 if f["traffic_class"] == "llm" else 0)
        
        # Create group identifier from flow_key
        flow_key = f.get("flow_key", {})
        group_id = f"{flow_key.get('src_ip', '')}_{flow_key.get('src_port', '')}_{flow_key.get('dst_ip', '')}_{flow_key.get('dst_port', '')}_{flow_key.get('protocol', '')}"
        groups.append(group_id)
    
    X = np.array(X_list)
    y = np.array(y_list)
    
    return X, y, groups, markov_models, block_mappings


def train_and_evaluate_models(
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
) -> Tuple[Dict[str, Any], Dict[str, Any], StandardScaler]:
    """Train RF, SVM, and XGBoost models, evaluate them, and return fitted models.
    
    Returns:
        results: Metrics for each model
        trained_models: Dict of fitted estimators
        scaler: Fitted StandardScaler (used for SVM)
    """
    results = {}
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Random Forest
    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    y_pred_rf = rf.predict(X_test)
    
    results["random_forest"] = {
        "accuracy": float(accuracy_score(y_test, y_pred_rf)),
        "precision": float(precision_score(y_test, y_pred_rf, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred_rf, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred_rf, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, y_pred_rf).tolist(),
        "classification_report": classification_report(y_test, y_pred_rf, target_names=["non_llm", "llm"], output_dict=True),
    }
    
    # SVM
    print("Training SVM...")
    svm = SVC(kernel="rbf", random_state=42, probability=True)
    svm.fit(X_train_scaled, y_train)
    y_pred_svm = svm.predict(X_test_scaled)
    
    results["svm"] = {
        "accuracy": float(accuracy_score(y_test, y_pred_svm)),
        "precision": float(precision_score(y_test, y_pred_svm, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred_svm, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred_svm, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, y_pred_svm).tolist(),
        "classification_report": classification_report(y_test, y_pred_svm, target_names=["non_llm", "llm"], output_dict=True),
    }
    
    # XGBoost
    print("Training XGBoost...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=100,
        random_state=42,
        eval_metric="logloss",
        use_label_encoder=False,
    )
    xgb_model.fit(X_train, y_train)
    y_pred_xgb = xgb_model.predict(X_test)
    
    results["xgboost"] = {
        "accuracy": float(accuracy_score(y_test, y_pred_xgb)),
        "precision": float(precision_score(y_test, y_pred_xgb, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred_xgb, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred_xgb, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, y_pred_xgb).tolist(),
        "classification_report": classification_report(y_test, y_pred_xgb, target_names=["non_llm", "llm"], output_dict=True),
    }
    
    trained_models = {
        "random_forest": rf,
        "svm": svm,
        "xgboost": xgb_model,
    }
    
    return results, trained_models, scaler


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Train classification models for LLM vs non-LLM flowlets"
    )
    p.add_argument("input", help="JSON file with flowlet features")
    p.add_argument(
        "--output",
        "-o",
        default="model_results.json",
        help="output JSON file for results",
    )
    p.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="fraction of data for testing (default: 0.2)",
    )
    p.add_argument(
        "--model-weights",
        default="flowlet_model_weights.pkl",
        help="path to save trained model weights/artifacts (joblib format)",
    )
    args = p.parse_args(argv)
    
    # Load features
    print(f"Loading features from {args.input}...")
    features = load_flowlet_features(args.input)
    print(f"Loaded {len(features)} flowlets")
    
    # Filter to ChatGPT only
    features = filter_chatgpt_only(features)
    print(f"Filtered to {len(features)} ChatGPT/non-LLM flowlets")
    
    # Prepare training data
    print("Preparing training data...")
    X, y, groups, markov_models, block_mappings = prepare_training_data(features)
    print(f"Feature matrix shape: {X.shape}")
    print(f"Class distribution: {np.bincount(y)}")
    
    # Split data by groups (flows stay together)
    print("Splitting data by flows...")
    gss = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups))
    
    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    
    print(f"Train set: {len(X_train)} flowlets")
    print(f"Test set: {len(X_test)} flowlets")
    print(f"Train class distribution: {np.bincount(y_train)}")
    print(f"Test class distribution: {np.bincount(y_test)}")
    
    # Train and evaluate models
    print("\nTraining models...")
    results, trained_models, scaler = train_and_evaluate_models(
        X_train, X_test, y_train, y_test
    )
    
    # Print results
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    for model_name, metrics in results.items():
        print(f"\n{model_name.upper()}:")
        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall:    {metrics['recall']:.4f}")
        print(f"  F1 Score:  {metrics['f1']:.4f}")
        print(f"  Confusion Matrix:")
        cm = metrics['confusion_matrix']
        print(f"    [[TN={cm[0][0]}, FP={cm[0][1]}],")
        print(f"     [FN={cm[1][0]}, TP={cm[1][1]}]]")
    
    # Save results
    output_data = {
        "dataset_info": {
            "total_flowlets": len(features),
            "train_size": len(X_train),
            "test_size": len(X_test),
            "feature_dim": X.shape[1],
            "train_class_distribution": np.bincount(y_train).tolist(),
            "test_class_distribution": np.bincount(y_test).tolist(),
        },
        "models": results,
    }
    
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\nResults saved to {args.output}")
    
    # Persist trained artifacts for later inference
    model_artifacts = {
        "models": trained_models,
        "scaler": scaler,
        "markov_models": markov_models,
        "block_mappings": block_mappings,
        "feature_dim": int(X.shape[1]),
        "labels": {"non_llm": 0, "llm": 1},
        "training_metadata": {
            "input_file": str(args.input),
            "test_size": args.test_size,
            "train_size": len(X_train),
            "test_size_count": len(X_test),
        },
    }
    
    joblib.dump(model_artifacts, args.model_weights)
    print(f"Model artifacts saved to {args.model_weights}")


if __name__ == "__main__":
    main()
