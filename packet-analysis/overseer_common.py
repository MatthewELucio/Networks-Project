#!/usr/bin/env python3
"""overseer_common.py

Shared utilities for the mixture-of-experts overseer models that combine
provider-specific flowlet classifiers.

Each provider (ChatGPT, Claude, Gemini) has its own expert module that builds 
Markov features plus statistical features. This module wraps that logic in 
an ``ExpertModel`` class so the overseers can:

    1. Train one expert per provider on that provider's flowlets (sensitive vs non-sensitive).
    2. Apply the expert to any flowlet and obtain ``P(sensitive | flowlet)``.
    3. Combine those probabilities into a single global sensitivity prediction.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

FlowletDict = Dict[str, Any]
FilterFn = Callable[[List[FlowletDict]], List[FlowletDict]]

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_SNAPSHOTS_ROOT = (
    BASE_DIR.parent / "data-pipeline" / "data" / "snapshots"
).resolve()
DEFAULT_MODELS_ROOT = (BASE_DIR / "trained_overseers").resolve()


def _load_module(module_name: str, file_path: Path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {file_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _filter_all_traffic(features: List[FlowletDict]) -> List[FlowletDict]:
    """Identity filter used by the optional global expert."""
    return list(features)


# Configuration for expert sources
EXPERT_SOURCES: Dict[str, Tuple[Path, Any]] = {
    "chatgpt": (BASE_DIR / "chatgpt" / "flowlet_models.py", "filter_chatgpt_only"),
    "claude": (BASE_DIR / "claude" / "flowlet_models_claude.py", "filter_claude_only"),
    "gemini": (BASE_DIR / "gemini" / "flowlet_models_gemini.py", "filter_gemini_only"),
    "all_providers": (BASE_DIR / "gemini" / "flowlet_models_gemini.py", _filter_all_traffic),
}

EXPERT_PROVIDERS: Tuple[str, ...] = ("chatgpt", "claude", "gemini")


@dataclass
class ExpertModel:
    """One provider-specific expert.

    Produces ``P(sensitive)`` for any flowlet using Markov models and RF classifiers.
    """

    name: str
    module: Any
    filter_fn: FilterFn
    markov_models: Dict[str, Any] = field(default_factory=dict)
    block_mappings: Dict[str, Dict[float, str]] = field(default_factory=dict)
    classifier: Any = None
    _sensitive_col: int = 1

    @classmethod
    def for_provider(cls, name: str) -> "ExpertModel":
        if name not in EXPERT_SOURCES:
            raise ValueError(f"Unknown expert provider: {name}")
        path, filter_spec = EXPERT_SOURCES[name]
        module = _load_module(f"overseer_expert_{name}", path)
        if callable(filter_spec):
            filter_fn = filter_spec
        else:
            filter_fn = getattr(module, filter_spec)
        return cls(name=name, module=module, filter_fn=filter_fn)

    def _extract_matrix(self, flowlets: Sequence[FlowletDict]) -> np.ndarray:
        if not flowlets:
            return np.zeros((0, 0))
        vectors = [
            self.module.extract_ml_features(
                f, self.markov_models, self.block_mappings
            )
            for f in flowlets
        ]
        return np.vstack(vectors)

    def fit(
        self,
        train_flowlets: Sequence[FlowletDict],
        *,
        n_estimators: int = 100,
        random_state: int = 42,
    ) -> "ExpertModel":
        """Fit Markov models + RandomForest on this expert's subset."""
        filtered = self.filter_fn(list(train_flowlets))
        if not filtered:
            raise ValueError(f"No training flowlets available for expert '{self.name}'")

        X, y, _groups, markov_models, block_mappings = (
            self.module.prepare_training_data(filtered)
        )
        self.markov_models = markov_models
        self.block_mappings = block_mappings

        clf = RandomForestClassifier(
            n_estimators=n_estimators,
            random_state=random_state,
            n_jobs=-1,
        )
        clf.fit(X, y)
        self.classifier = clf

        classes = list(clf.classes_)
        # Label 1 is 'sensitive'
        self._sensitive_col = classes.index(1) if 1 in classes else len(classes) - 1
        return self

    def predict_proba_sensitive(self, flowlets: Sequence[FlowletDict]) -> np.ndarray:
        """Return the expert's ``P(sensitive | flowlet)``."""
        if self.classifier is None:
            raise RuntimeError(f"Expert '{self.name}' has not been fitted")
        if not flowlets:
            return np.zeros(0, dtype=float)

        X = self._extract_matrix(flowlets)
        probs = self.classifier.predict_proba(X)
        if probs.shape[1] == 1:
            only_class = self.classifier.classes_[0]
            return np.full(probs.shape[0], 1.0 if only_class == 1 else 0.0)
        return probs[:, self._sensitive_col]

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "name": self.name,
                "markov_models": self.markov_models,
                "block_mappings": self.block_mappings,
                "classifier": self.classifier,
                "sensitive_col": self._sensitive_col,
            },
            path,
        )

    @classmethod
    def from_saved(cls, path: Path) -> "ExpertModel":
        path = Path(path)
        state = joblib.load(path)
        expert = cls.for_provider(state["name"])
        expert.markov_models = state.get("markov_models", {})
        expert.block_mappings = state.get("block_mappings", {})
        expert.classifier = state["classifier"]
        expert._sensitive_col = int(state.get("sensitive_col", state.get("llm_col", 1)))
        return expert


# ---------------------------------------------------------------------------
# Snapshot Discovery & Utils
# ---------------------------------------------------------------------------

def list_snapshots(root: Optional[Path] = None) -> List[Path]:
    root_path = Path(root) if root else DEFAULT_SNAPSHOTS_ROOT
    if not root_path.exists():
        return []
    snapshots = [
        p for p in root_path.iterdir()
        if p.is_dir() and (p / "captures").is_dir()
    ]
    return sorted(snapshots, key=lambda p: p.name)


def latest_snapshot(root: Optional[Path] = None) -> Optional[Path]:
    snaps = list_snapshots(root)
    return snaps[-1] if snaps else None


def _derive_source_file(flowlet: FlowletDict, fallback: str) -> str:
    existing = flowlet.get("source_file")
    if existing:
        return str(existing)
    # Heuristic: sensitive/non-sensitive captures usually still come from a provider/process
    source_hint = (flowlet.get("llm_name") or flowlet.get("process_name") or "").strip().lower()
    return source_hint if source_hint else fallback


def load_flowlets_from_snapshot(snapshot_dir: Path) -> List[FlowletDict]:
    """Load flowlets and propagate the capture-level sensitivity label."""
    sd = Path(snapshot_dir)
    captures = sd / "captures"
    if not captures.is_dir():
        raise FileNotFoundError(f"No captures/ directory inside {sd}")

    all_flowlets: List[FlowletDict] = []
    capture_files = sorted(captures.glob("*.json"))

    for path in capture_files:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        
        # Pull the capture-level sensitivity (e.g., "sensitive" or "non-sensitive")
        capture_sensitivity = data.get("sensitivity")
        flowlets = data.get("flowlets", []) if isinstance(data, dict) else []
        
        fallback = path.stem
        for fl in flowlets:
            fl["source_file"] = _derive_source_file(fl, fallback)
            # Hoist the capture label so the labeler can see it
            if capture_sensitivity:
                fl["sensitivity_captured"] = capture_sensitivity
            all_flowlets.append(fl)

    return all_flowlets


# ---------------------------------------------------------------------------
# Labeling and Splitting (Sensitive = 1, Non-Sensitive = 0)
# ---------------------------------------------------------------------------

def flowlet_labels(flowlets: Sequence[FlowletDict]) -> np.ndarray:
    """Binary label for each flowlet (1 = sensitive, 0 = non-sensitive)."""
    labels = []
    for f in flowlets:
        # Priority 1: The hoisted sensitivity label from the capture file
        # Priority 2: The individual flowlet's traffic_class
        label_val = f.get("sensitivity_captured") or f.get("traffic_class") or ""
        label_str = str(label_val).lower()

        if label_str in ["sensitive", "llm"]:
            labels.append(1)
        elif label_str in ["non-sensitive", "non_sensitive", "non_llm", "benign"]:
            labels.append(0)
        else:
            # Fallback to filename patterns
            source = f.get("source_file", "").lower()
            if "non-sensitive" in source or "non_sensitive" in source:
                labels.append(0)
            else:
                labels.append(1)
                
    y = np.array(labels, dtype=int)
    
    # Print the specific counts using your new terminology
    n_sensitive = np.sum(y == 1)
    n_non_sensitive = np.sum(y == 0)
    print(f"Sensitive flowlets: {n_sensitive}")
    print(f"Non-Sensitive flowlets: {n_non_sensitive}")
    
    return y


def flowlet_groups(flowlets: Sequence[FlowletDict]) -> List[str]:
    groups = []
    for f in flowlets:
        k = f.get("flow_key", {}) or {}
        groups.append(
            f"{k.get('src_ip','')}_{k.get('src_port','')}_"
            f"{k.get('dst_ip','')}_{k.get('dst_port','')}_{k.get('protocol','')}"
        )
    return groups


def split_by_groups(
    flowlets: Sequence[FlowletDict],
    test_size: float = 0.2,
    random_state: int = 42,
) -> Tuple[List[FlowletDict], List[FlowletDict]]:
    if not flowlets:
        return [], []
    groups = flowlet_groups(flowlets)
    y = flowlet_labels(flowlets)
    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_idx, test_idx = next(gss.split(np.zeros(len(flowlets)), y, groups))
    return [flowlets[i] for i in train_idx], [flowlets[i] for i in test_idx]


def build_experts(providers: Iterable[str] = EXPERT_PROVIDERS) -> List[ExpertModel]:
    return [ExpertModel.for_provider(p) for p in providers]


def stack_expert_probabilities(
    experts: Sequence[ExpertModel],
    flowlets: Sequence[FlowletDict],
) -> np.ndarray:
    """Return (n_flowlets, n_experts) matrix of P(sensitive)."""
    if not flowlets:
        return np.zeros((0, len(experts)))
    cols = [exp.predict_proba_sensitive(flowlets) for exp in experts]
    return np.vstack(cols).T


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_binary_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_score: Optional[np.ndarray] = None,
) -> Dict[str, Any]:
    metrics: Dict[str, Any] = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        "classification_report": classification_report(
            y_true,
            y_pred,
            target_names=["non-sensitive", "sensitive"],
            output_dict=True,
            zero_division=0,
        ),
    }
    if y_score is not None and len(np.unique(y_true)) == 2:
        try:
            metrics["roc_auc"] = float(roc_auc_score(y_true, y_score))
        except ValueError:
            metrics["roc_auc"] = None
    return metrics


def print_metrics_block(title: str, metrics: Dict[str, Any]) -> None:
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1 Score:  {metrics['f1']:.4f}")
    if metrics.get("roc_auc") is not None:
        print(f"  ROC-AUC:   {metrics['roc_auc']:.4f}")
    cm = metrics["confusion_matrix"]
    print("  Confusion Matrix:")
    print(f"    [[TN={cm[0][0]}, FP={cm[0][1]}],")
    print(f"     [FN={cm[1][0]}, TP={cm[1][1]}]]")


# ---------------------------------------------------------------------------
# UI Helpers & Directories
# ---------------------------------------------------------------------------

def _prompt(prompt_text: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    try: answer = input(f"{prompt_text}{suffix}: ").strip()
    except EOFError: answer = ""
    return answer or (default or "")


def prompt_snapshot_dir(root: Optional[Path] = None, default: Optional[Path] = None) -> Path:
    snapshots = list_snapshots(root)
    if default is None:
        default = snapshots[-1] if snapshots else None
    if not snapshots:
        fallback = _prompt("No snapshots found. Enter path manually", str(default) if default else None)
        return Path(fallback).expanduser().resolve()

    print("\nAvailable snapshots:")
    for idx, snap in enumerate(snapshots, 1):
        marker = "  (default)" if default and snap == default else ""
        print(f"  [{idx}] {snap.name}{marker}")

    response = _prompt("Choose snapshot (# or path)", default.name if default else None)
    if not response: return default
    if response.isdigit():
        pick = int(response)
        if 1 <= pick <= len(snapshots): return snapshots[pick - 1]
    candidate = Path(response).expanduser()
    if not candidate.is_absolute():
        candidate = (root or DEFAULT_SNAPSHOTS_ROOT) / candidate
    return candidate.resolve()


def prompt_mode(default: str = "train") -> str:
    while True:
        raw = _prompt("Mode: (t)rain or (l)oad?", default=default).lower()
        if raw in ("t", "train"): return "train"
        if raw in ("l", "load"): return "load"


def list_trained_dirs(models_root: Path, prefix: str) -> List[Path]:
    root = Path(models_root)
    if not root.exists(): return []
    return sorted([d for d in root.iterdir() if d.is_dir() and d.name.startswith(prefix)], key=lambda p: p.name)


def prompt_load_dir(models_root: Path, prefix: str, default: Optional[Path] = None) -> Path:
    dirs = list_trained_dirs(models_root, prefix)
    if default is None: default = dirs[-1] if dirs else None
    if not dirs:
        fallback = _prompt(f"No models with prefix '{prefix}' found. Path", str(default) if default else None)
        return Path(fallback).expanduser().resolve()

    print("\nAvailable trained overseers:")
    for idx, path in enumerate(dirs, 1):
        marker = "  (default)" if default and path == default else ""
        print(f"  [{idx}] {path.name}{marker}")

    response = _prompt("Choose trained overseer (# or path)", default.name if default else None)
    if not response: return default
    if response.isdigit():
        pick = int(response)
        if 1 <= pick <= len(dirs): return dirs[pick - 1]
    candidate = Path(response).expanduser()
    if not candidate.is_absolute(): candidate = Path(models_root) / candidate
    return candidate.resolve()


def make_timestamped_dir(models_root: Path, prefix: str) -> Path:
    root = Path(models_root)
    root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = root / f"{prefix}_{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "experts").mkdir(parents=True, exist_ok=True)
    return out


def write_manifest(out_dir: Path, manifest: Dict[str, Any]) -> None:
    path = Path(out_dir) / "manifest.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, default=str)


def read_manifest(in_dir: Path) -> Dict[str, Any]:
    path = Path(in_dir) / "manifest.json"
    if not path.exists(): return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)