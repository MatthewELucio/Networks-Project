#!/usr/bin/env python3
"""flowlet_models.py

Train classification models to distinguish Sensitive vs Non-Sensitive flowlets
specifically for ChatGPT-related traffic.
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
import xgboost as xgb


def load_flowlet_features(filepath: str) -> List[Dict[str, Any]]:
    """Load flowlet features from JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def filter_chatgpt_only(features: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filter to only ChatGPT (sensitive) vs all non-sensitive flowlets."""
    filtered = []
    for f in features:
        source = str(f.get("source_file", "")).lower()
        
        # Use hoisted sensitivity label or metadata
        eff_class = f.get("sensitivity_captured") or f.get("traffic_class") or ""
        eff_class = str(eff_class).lower()

        is_non_sensitive = (
            eff_class in ["non-sensitive", "non_sensitive", "non_llm", "benign"] 
            or "non-sensitive" in source
        )
        
        # Logic: Keep if it is ChatGPT sensitive traffic OR if it is any non-sensitive traffic
        if ("chatgpt" in source and not is_non_sensitive) or is_non_sensitive:
            filtered.append(f)
    
    return filtered


def bucket_time_gaps(time_gaps: List[float]) -> List[str]:
    """Bucket time gaps into discrete states."""
    buckets = []
    for gap in time_gaps:
        gap_ms = gap * 1000
        if gap_ms < 10: buckets.append("GAP_0_10ms")
        elif gap_ms < 100: buckets.append("GAP_10_100ms")
        elif gap_ms < 1000: buckets.append("GAP_100ms_1s")
        else: buckets.append("GAP_GT_1s")
    return buckets


def build_power_law_blocks(values: List[float], coverage: float = 0.9) -> Tuple[List[float], Dict[float, str]]:
    if not values: return [], {}
    value_counts = Counter(values)
    total_count = len(values)
    sorted_values = sorted(value_counts.items(), key=lambda x: x[1], reverse=True)
    
    cumulative = 0
    blocks = []
    for value, count in sorted_values:
        blocks.append(value)
        cumulative += count
        if cumulative / total_count >= coverage: break
    
    value_to_block = {}
    for val in set(values):
        if val in blocks:
            value_to_block[val] = f"BLOCK_{val:.2f}"
        else:
            nearest = min(blocks, key=lambda b: abs(b - val))
            value_to_block[val] = f"BLOCK_{nearest:.2f}"
    return blocks, value_to_block


def build_markov_model(sequences: List[List[str]]) -> Dict[str, Any]:
    transition_counts = defaultdict(lambda: defaultdict(int))
    start_counts = defaultdict(int)
    total_sequences = len(sequences)
    
    for seq in sequences:
        if not seq: continue
        start_counts[seq[0]] += 1
        for i in range(len(seq) - 1):
            transition_counts[seq[i]][seq[i + 1]] += 1
    
    transition_probs = {}
    for state, next_states in transition_counts.items():
        total = sum(next_states.values())
        transition_probs[state] = {next_state: count / total for next_state, count in next_states.items()}
    
    return {
        "transition_probs": transition_probs,
        "start_probs": {s: c / total_sequences for s, c in start_counts.items()},
    }


def compute_sequence_log_likelihood(sequence: List[str], markov_model: Dict[str, Any]) -> float:
    if not sequence: return -np.inf
    tp = markov_model.get("transition_probs", {})
    sp = markov_model.get("start_probs", {})
    
    log_prob = np.log(sp.get(sequence[0], 1e-10))
    for i in range(len(sequence) - 1):
        curr, nxt = sequence[i], sequence[i+1]
        prob = tp.get(curr, {}).get(nxt, 1e-10)
        log_prob += np.log(prob + 1e-10)
    
    return log_prob / len(sequence)


def extract_ml_features(
    flowlet: Dict[str, Any], 
    markov_models: Dict[str, Dict[str, Any]], 
    block_mappings: Dict[str, Dict[float, str]]
) -> np.ndarray:
    features = [
        flowlet.get("duration", 0.0),
        flowlet.get("packet_count", 0),
        flowlet.get("total_bytes", 0),
        flowlet.get("inter_packet_time_mean", 0.0),
        flowlet.get("inter_packet_time_std", 0.0),
        flowlet.get("packet_size_mean", 0.0),
        flowlet.get("packet_size_std", 0.0)
    ]
    
    time_gap_seq = bucket_time_gaps(flowlet.get("inter_packet_times", []))
    packet_sizes = flowlet.get("packet_sizes", [])
    
    # Use sensitive block mapping for extraction if available
    size_block_seq = []
    if "sensitive" in block_mappings:
        size_block_seq = [block_mappings["sensitive"].get(s, f"BLOCK_{s:.2f}") for s in packet_sizes]

    for cls in ["sensitive", "non-sensitive"]:
        if cls in markov_models:
            ll_time = compute_sequence_log_likelihood(time_gap_seq, markov_models[cls]["time_gap"])
            features.append(np.clip(ll_time, -100.0, 0.0))
            
            if size_block_seq:
                ll_size = compute_sequence_log_likelihood(size_block_seq, markov_models[cls]["size_block"])
                features.append(np.clip(ll_size, -100.0, 0.0))
            else:
                features.append(-100.0)
        else:
            features.extend([-100.0, -100.0])
    
    return np.array(features)


def prepare_training_data(features: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray, List[str], Dict[str, Any], Dict[str, Dict[float, str]]]:
    y_labels = []
    for f in features:
        source = str(f.get("source_file", "")).lower()
        eff_class = f.get("sensitivity_captured") or f.get("traffic_class") or ""
        eff_class = str(eff_class).lower()
        
        if eff_class in ["non-sensitive", "non_sensitive", "non_llm", "benign"] or "non-sensitive" in source:
            y_labels.append(0)
        else:
            y_labels.append(1)

    y = np.array(y_labels)
    sensitive_flowlets = [f for i, f in enumerate(features) if y[i] == 1]
    non_sensitive_flowlets = [f for i, f in enumerate(features) if y[i] == 0]

    print(f"Sensitive flowlets: {len(sensitive_flowlets)}")
    print(f"Non-Sensitive flowlets: {len(non_sensitive_flowlets)}")

    # Markov Setup
    block_mappings = {}
    for cls, flowlets in [("sensitive", sensitive_flowlets), ("non-sensitive", non_sensitive_flowlets)]:
        all_sizes = [s for f in flowlets for s in f.get("packet_sizes", [])]
        if all_sizes:
            _, mapping = build_power_law_blocks(all_sizes)
            block_mappings[cls] = mapping

    markov_models = {}
    for cls, flowlets in [("sensitive", sensitive_flowlets), ("non-sensitive", non_sensitive_flowlets)]:
        time_seqs = [bucket_time_gaps(f.get("inter_packet_times", [])) for f in flowlets]
        size_seqs = [[block_mappings[cls].get(s, f"BLOCK_{s:.2f}") for s in f.get("packet_sizes", [])] for f in flowlets] if cls in block_mappings else []
        markov_models[cls] = {
            "time_gap": build_markov_model(time_seqs),
            "size_block": build_markov_model(size_seqs),
        }
        print(f"{cls}: Built Markov models")

    X = np.array([extract_ml_features(f, markov_models, block_mappings) for f in features])
    groups = [f"{f.get('flow_key', {}).get('src_ip')}_{f.get('flow_key', {}).get('src_port')}" for f in features]
    
    return X, y, groups, markov_models, block_mappings


def train_and_evaluate_models(X_train, X_test, y_train, y_test) -> Dict[str, Any]:
    results = {}
    
    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1).fit(X_train, y_train)
    y_pred = rf.predict(X_test)
    results["random_forest"] = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "classification_report": classification_report(y_test, y_pred, target_names=["non-sensitive", "sensitive"], output_dict=True, zero_division=0),
    }

    print("Training XGBoost...")
    xgb_model = xgb.XGBClassifier(n_estimators=100, random_state=42, eval_metric="logloss").fit(X_train, y_train)
    y_pred_xgb = xgb_model.predict(X_test)
    results["xgboost"] = {
        "accuracy": float(accuracy_score(y_test, y_pred_xgb)),
        "precision": float(precision_score(y_test, y_pred_xgb, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred_xgb, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred_xgb, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, y_pred_xgb).tolist(),
        "classification_report": classification_report(y_test, y_pred_xgb, target_names=["non-sensitive", "sensitive"], output_dict=True, zero_division=0),
    }
    return results


def main(argv=None):
    p = argparse.ArgumentParser(description="Train classification models for ChatGPT Sensitivity")
    p.add_argument("input", help="JSON file with flowlet features")
    p.add_argument("--output", "-o", default="results_chatgpt.json")
    p.add_argument("--test-size", type=float, default=0.2)
    args = p.parse_args(argv)
    
    print(f"Loading features from {args.input}...")
    raw_features = load_flowlet_features(args.input)
    features = filter_chatgpt_only(raw_features)
    print(f"Filtered to {len(features)} ChatGPT/non-sensitive flowlets")
    
    if len(features) == 0:
        print("Error: No flowlets found matching ChatGPT criteria.")
        return

    X, y, groups, m_models, b_mappings = prepare_training_data(features)
    
    gss = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=42)
    try:
        train_idx, test_idx = next(gss.split(X, y, groups))
    except StopIteration:
        print("Error: Not enough data to perform a split.")
        return
    
    results = train_and_evaluate_models(X[train_idx], X[test_idx], y[train_idx], y[test_idx])
    
    print("\n" + "=" * 60)
    print("RESULTS - CHATGPT SENSITIVITY")
    print("=" * 60)
    for name, m in results.items():
        print(f"{name.upper()}: Acc={m['accuracy']:.4f}, Prec={m['precision']:.4f}, Rec={m['recall']:.4f}")

    with open(args.output, "w") as f:
        json.dump({"dataset": len(features), "models": results}, f, indent=2)

if __name__ == "__main__":
    main()