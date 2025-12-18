#!/usr/bin/env python3
"""classify.py

Load trained flowlet classification artifacts, score new flowlets, and append
predictions. Designed so the data loader can be swapped (JSON today, SQL later).

Usage:
    python3 classify.py --input flowlets.json --model-weights flowlet_model_weights.pkl \
        --output classified_flowlets.json
"""
import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np

from flowlet_models import extract_ml_features


# Map numeric label to a human-readable tag. The training data is currently
# binary (ChatGPT vs non-LLM), so we expose those strings for downstream use.
LABEL_MAP = {1: "ChatGPT", 0: "non_llm"}


def load_flowlets_from_json(path: Path) -> List[Dict[str, Any]]:
    """Load flowlet records from a JSON file."""
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_flowlets_from_sql(db_path: str, capture_id: str | None = None) -> List[Dict[str, Any]]:
    """Load flowlet records from SQLite database."""
    from database import init_database, get_db_session, Flowlet
    
    init_database(db_path)
    db = get_db_session()
    
    try:
        query = db.query(Flowlet)
        if capture_id:
            query = query.filter_by(capture_id=int(capture_id))
        
        flowlets = query.all()
        return [flowlet.to_dict() for flowlet in flowlets]
    finally:
        db.close()


def load_flowlets(input_path: Path, source_type: str, sql_query: str | None) -> List[Dict[str, Any]]:
    """Dispatch to the appropriate loader based on the source type."""
    if source_type == "json":
        return load_flowlets_from_json(input_path)
    if source_type == "sql":
        return load_flowlets_from_sql(str(input_path), sql_query)
    raise ValueError(f"Unsupported source type: {source_type}")


def load_model_artifacts(path: Path) -> Dict[str, Any]:
    """Load serialized training artifacts needed for inference."""
    artifacts = joblib.load(path)
    required_keys = ["models", "scaler", "markov_models", "block_mappings"]
    missing = [k for k in required_keys if k not in artifacts]
    if missing:
        raise KeyError(f"Missing required artifact keys: {missing}")
    return artifacts


def compute_model_probabilities(
    feature_vec: np.ndarray,
    models: Dict[str, Any],
    scaler: Any | None,
) -> Dict[str, float]:
    """Compute P(llm) for each model in the ensemble."""
    probs: Dict[str, float] = {}
    feature_vec = feature_vec.reshape(1, -1)
    
    if "random_forest" in models and hasattr(models["random_forest"], "predict_proba"):
        probs["random_forest"] = float(models["random_forest"].predict_proba(feature_vec)[0, 1])
    
    if "svm" in models and hasattr(models["svm"], "predict_proba"):
        scaled = scaler.transform(feature_vec) if scaler is not None else feature_vec
        probs["svm"] = float(models["svm"].predict_proba(scaled)[0, 1])
    
    if "xgboost" in models and hasattr(models["xgboost"], "predict_proba"):
        probs["xgboost"] = float(models["xgboost"].predict_proba(feature_vec)[0, 1])
    
    return probs


def choose_label_and_confidence(
    probs: Dict[str, float],
    threshold: float = 0.5,
) -> Tuple[int, float]:
    """Combine ensemble probabilities into a label and confidence score.
    
    Label is decided by the mean P(llm). Confidence is the highest probability
    among ensemble members for the chosen label.
    """
    if not probs:
        return 0, 0.0
    
    ensemble_mean = float(np.mean(list(probs.values())))
    predicted_label = 1 if ensemble_mean >= threshold else 0
    
    if predicted_label == 1:
        confidence = max(probs.values())
    else:
        confidence = max(1.0 - p for p in probs.values())
    
    return predicted_label, float(confidence)


def annotate_flowlets(
    flowlets: List[Dict[str, Any]],
    artifacts: Dict[str, Any],
    threshold: float = 0.5,
) -> List[Dict[str, Any]]:
    """Attach prediction fields to each flowlet."""
    markov_models = artifacts["markov_models"]
    block_mappings = artifacts["block_mappings"]
    models = artifacts["models"]
    scaler = artifacts.get("scaler")
    
    annotated = []
    for flowlet in flowlets:
        features = extract_ml_features(flowlet, markov_models, block_mappings)
        probs = compute_model_probabilities(features, models, scaler)
        label, confidence = choose_label_and_confidence(probs, threshold)
        
        flowlet_with_prediction = dict(flowlet)
        flowlet_with_prediction["model_llm_prediction"] = LABEL_MAP.get(label, "unknown")
        flowlet_with_prediction["model_llm_confidence"] = confidence
        annotated.append(flowlet_with_prediction)
    
    return annotated


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Classify flowlets as LLM or non-LLM using trained artifacts."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to input flowlets (JSON today; swap loader for SQL later).",
    )
    parser.add_argument(
        "--input-type",
        choices=["json", "sql"],
        default="json",
        help="Select the data source type (default: json).",
    )
    parser.add_argument(
        "--sql-query",
        default=None,
        help="Optional SQL query if using --input-type sql (placeholder).",
    )
    parser.add_argument(
        "--model-weights",
        default="flowlet_model_weights.pkl",
        help="Path to trained model artifacts produced by flowlet_models.py.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="classified_flowlets.json",
        help="Path to write annotated flowlets with predictions.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Ensemble mean probability threshold for LLM classification.",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    
    input_path = Path(args.input)
    output_path = Path(args.output)
    model_path = Path(args.model_weights)
    
    print(f"Loading model artifacts from {model_path}...")
    artifacts = load_model_artifacts(model_path)
    
    print(f"Loading flowlets from {input_path} using source type '{args.input_type}'...")
    flowlets = load_flowlets(input_path, args.input_type, args.sql_query)
    print(f"Loaded {len(flowlets)} flowlets")
    
    print("Running predictions...")
    annotated_flowlets = annotate_flowlets(flowlets, artifacts, threshold=args.threshold)
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(annotated_flowlets, f, indent=2)
    
    print(f"Saved predictions to {output_path}")


if __name__ == "__main__":
    main()

