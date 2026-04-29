#!/usr/bin/env python3
"""overseer_common.py

Shared utilities for the mixture-of-experts overseer models that combine
the three provider-specific flowlet classifiers (ChatGPT, Claude, Gemini).

Each provider has its own training script that builds MaMPF-style Markov
features plus statistical features and trains a binary LLM-vs-non-LLM
classifier. This module wraps that logic in an ``ExpertModel`` class so
the overseers can:

    1. Train one expert per provider on that provider's flowlets + non-LLM.
    2. Apply the expert to any flowlet (including flowlets from other
       providers) and obtain ``P(llm | flowlet)`` from the expert's
       perspective.
    3. Combine those per-expert probabilities into a single "is this
       flowlet produced by any LLM?" prediction.

It also centralises snapshot discovery, interactive prompts, and
PKL serialization so ``overseer_max.py`` and ``overseer_stacked.py`` can
share the same train/load flow.
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


# ---------------------------------------------------------------------------
# Dynamic loading of the provider-specific expert modules.
# ---------------------------------------------------------------------------
def _load_module(module_name: str, file_path: Path):
    """Load a Python source file as a uniquely-named module.

    The three expert scripts share the same unqualified module name
    (``flowlet_models``), so we load them through importlib with distinct
    internal names to avoid collisions in ``sys.modules``.
    """
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {file_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _filter_all_llm(features: List[FlowletDict]) -> List[FlowletDict]:
    """Identity filter used by the optional 4th expert.

    The three provider-specific filters each keep only one provider's LLM
    flowlets plus all non-LLM flowlets. The ``all_llm`` expert should
    instead train on *every* LLM flowlet (ChatGPT, Claude, Gemini) plus
    non-LLM, so its filter simply returns the input unchanged.
    """
    return list(features)


# Each entry is ``(module_path, filter_spec)`` where ``filter_spec`` is
# either the name of a filter function defined on that module, or a
# callable that filters a list of flowlets directly.
EXPERT_SOURCES: Dict[str, Tuple[Path, Any]] = {
    "chatgpt": (BASE_DIR / "chatgpt" / "flowlet_models.py", "filter_chatgpt_only"),
    "claude": (BASE_DIR / "claude" / "flowlet_models_claude.py", "filter_claude_only"),
    "gemini": (BASE_DIR / "gemini" / "flowlet_models_gemini.py", "filter_gemini_only"),
    # "all_llm" reuses Gemini's feature-extraction module (identical to
    # the other two) but trains on every LLM flowlet instead of just one
    # provider's. Use it as an optional 4th expert in the stacked overseer.
    "all_llm": (BASE_DIR / "gemini" / "flowlet_models_gemini.py", _filter_all_llm),
}

EXPERT_PROVIDERS: Tuple[str, ...] = ("chatgpt", "claude", "gemini")


@dataclass
class ExpertModel:
    """One provider-specific expert.

    Wraps the provider's feature-extraction primitives (Markov models
    over packet-size blocks and inter-packet-time buckets, plus basic
    statistical features) and a fitted scikit-learn classifier that
    produces ``P(llm)`` for any flowlet.
    """

    name: str
    module: Any
    filter_fn: FilterFn
    markov_models: Dict[str, Any] = field(default_factory=dict)
    block_mappings: Dict[str, Dict[float, str]] = field(default_factory=dict)
    classifier: Any = None
    _llm_col: int = 1

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
        """Fit Markov models + RandomForest on this expert's subset of
        ``train_flowlets`` (its own provider + non-LLM)."""

        filtered = self.filter_fn(list(train_flowlets))
        if not filtered:
            raise ValueError(
                f"No training flowlets available for expert '{self.name}'"
            )

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
        self._llm_col = classes.index(1) if 1 in classes else len(classes) - 1
        return self

    def predict_proba_llm(self, flowlets: Sequence[FlowletDict]) -> np.ndarray:
        """Return the expert's ``P(llm | flowlet)`` for every flowlet."""
        if self.classifier is None:
            raise RuntimeError(f"Expert '{self.name}' has not been fitted")
        if not flowlets:
            return np.zeros(0, dtype=float)

        X = self._extract_matrix(flowlets)
        probs = self.classifier.predict_proba(X)
        # Guard against single-class fallback (e.g. all non-LLM in a fold).
        if probs.shape[1] == 1:
            only_class = self.classifier.classes_[0]
            return np.full(probs.shape[0], 1.0 if only_class == 1 else 0.0)
        return probs[:, self._llm_col]

    # ------------------------------------------------------------------
    # Serialization. We only pickle picklable state; the dynamically
    # loaded provider module is re-imported on ``load``.
    # ------------------------------------------------------------------
    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "name": self.name,
                "markov_models": self.markov_models,
                "block_mappings": self.block_mappings,
                "classifier": self.classifier,
                "llm_col": self._llm_col,
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
        expert._llm_col = int(state.get("llm_col", 1))
        return expert


# ---------------------------------------------------------------------------
# Snapshot discovery & loading.
# ---------------------------------------------------------------------------
def list_snapshots(root: Optional[Path] = None) -> List[Path]:
    """Return snapshot directories (containing ``captures/``), oldest first."""
    root_path = Path(root) if root else DEFAULT_SNAPSHOTS_ROOT
    if not root_path.exists():
        return []
    snapshots = [
        p
        for p in root_path.iterdir()
        if p.is_dir() and (p / "captures").is_dir()
    ]
    return sorted(snapshots, key=lambda p: p.name)


def latest_snapshot(root: Optional[Path] = None) -> Optional[Path]:
    snaps = list_snapshots(root)
    return snaps[-1] if snaps else None


def _derive_source_file(flowlet: FlowletDict, fallback: str) -> str:
    """Produce a ``source_file`` string so provider filter functions
    (which look for 'chatgpt'/'claude'/'gemini' substrings) keep working
    on snapshot flowlets that lack a ``source_file`` field."""

    existing = flowlet.get("source_file")
    if existing:
        return str(existing)
    llm_name = (flowlet.get("llm_name") or "").strip().lower()
    if llm_name:
        return llm_name
    return fallback


def load_flowlets_from_snapshot(snapshot_dir: Path) -> List[FlowletDict]:
    """Load every flowlet from a snapshot's ``captures/*.json`` files.

    Each flowlet is annotated with ``source_file`` derived from its
    ``llm_name`` (or capture stem) so the provider-specific filter
    functions can still partition the data correctly.
    """
    sd = Path(snapshot_dir)
    captures = sd / "captures"
    if not captures.is_dir():
        raise FileNotFoundError(f"No captures/ directory inside {sd}")

    all_flowlets: List[FlowletDict] = []
    capture_files = sorted(captures.glob("*.json"))
    if not capture_files:
        raise FileNotFoundError(f"No capture JSON files in {captures}")

    for path in capture_files:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        flowlets = data.get("flowlets", []) if isinstance(data, dict) else []
        fallback = path.stem
        for fl in flowlets:
            fl["source_file"] = _derive_source_file(fl, fallback)
            all_flowlets.append(fl)

    return all_flowlets


# ---------------------------------------------------------------------------
# Labelling, grouping, splitting.
# ---------------------------------------------------------------------------
def load_all_features(path: str) -> List[FlowletDict]:
    """Backwards-compatible loader for a flat JSON list of flowlets."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(
            f"Expected a JSON list of flowlets in {path}, got {type(data).__name__}"
        )
    return data


def flowlet_labels(flowlets: Sequence[FlowletDict]) -> np.ndarray:
    """Binary ``is LLM`` label for each flowlet (1 = any LLM, 0 = non_llm)."""
    return np.array(
        [1 if f.get("traffic_class") == "llm" else 0 for f in flowlets],
        dtype=int,
    )


def flowlet_groups(flowlets: Sequence[FlowletDict]) -> List[str]:
    """Flow-level group ids so train/test splits never share a 5-tuple."""
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
    """Hold out entire flows (group-aware) for the test split."""
    if not flowlets:
        return [], []
    groups = flowlet_groups(flowlets)
    y = flowlet_labels(flowlets)
    gss = GroupShuffleSplit(
        n_splits=1, test_size=test_size, random_state=random_state
    )
    train_idx, test_idx = next(gss.split(np.zeros(len(flowlets)), y, groups))
    train = [flowlets[i] for i in train_idx]
    test = [flowlets[i] for i in test_idx]
    return train, test


def build_experts(
    providers: Iterable[str] = EXPERT_PROVIDERS,
) -> List[ExpertModel]:
    return [ExpertModel.for_provider(p) for p in providers]


def stack_expert_probabilities(
    experts: Sequence[ExpertModel],
    flowlets: Sequence[FlowletDict],
) -> np.ndarray:
    """Return an ``(n_flowlets, n_experts)`` matrix of ``P(llm)``."""
    if not flowlets:
        return np.zeros((0, len(experts)))
    cols = [exp.predict_proba_llm(flowlets) for exp in experts]
    return np.vstack(cols).T


# ---------------------------------------------------------------------------
# Metrics reporting.
# ---------------------------------------------------------------------------
def compute_binary_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_score: Optional[np.ndarray] = None,
) -> Dict[str, Any]:
    """Standard evaluation bundle mirroring the per-expert scripts."""
    metrics: Dict[str, Any] = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        "classification_report": classification_report(
            y_true,
            y_pred,
            target_names=["non_llm", "llm"],
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
# Interactive prompts (all CLI-overridable by callers).
# ---------------------------------------------------------------------------
def _prompt(prompt_text: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    try:
        answer = input(f"{prompt_text}{suffix}: ").strip()
    except EOFError:
        answer = ""
    return answer or (default or "")


def prompt_snapshot_dir(
    snapshots_root: Optional[Path] = None,
    default: Optional[Path] = None,
) -> Path:
    """Let the user pick a snapshot directory, defaulting to the newest."""
    snapshots = list_snapshots(snapshots_root)
    if default is None:
        default = snapshots[-1] if snapshots else None

    if not snapshots:
        fallback = _prompt(
            "No snapshots found. Enter a snapshot path manually",
            default=str(default) if default else None,
        )
        if not fallback:
            raise FileNotFoundError("No snapshot directory provided.")
        return Path(fallback).expanduser().resolve()

    print("\nAvailable snapshots:")
    for idx, snap in enumerate(snapshots, 1):
        marker = "  (default)" if default is not None and snap == default else ""
        print(f"  [{idx}] {snap.name}{marker}")

    response = _prompt(
        "Choose snapshot (# or path)",
        default=default.name if default else None,
    )

    if not response:
        if default is None:
            raise FileNotFoundError("No snapshot selected.")
        return default
    if response.isdigit():
        pick = int(response)
        if 1 <= pick <= len(snapshots):
            return snapshots[pick - 1]
        raise ValueError(f"Snapshot index out of range: {pick}")
    # Allow either a bare snapshot name or a path.
    candidate = Path(response).expanduser()
    if not candidate.is_absolute():
        candidate = (snapshots_root or DEFAULT_SNAPSHOTS_ROOT) / candidate
    return candidate.resolve()


def prompt_mode(default: str = "train") -> str:
    while True:
        raw = _prompt(
            "Mode: (t)rain new models or (l)oad existing PKLs?",
            default=default,
        ).lower()
        if raw in ("t", "train"):
            return "train"
        if raw in ("l", "load"):
            return "load"
        print("  Please answer 't' or 'l'.")


def list_trained_dirs(models_root: Path, prefix: str) -> List[Path]:
    root = Path(models_root)
    if not root.exists():
        return []
    return sorted(
        [d for d in root.iterdir() if d.is_dir() and d.name.startswith(prefix)],
        key=lambda p: p.name,
    )


def prompt_load_dir(
    models_root: Path,
    prefix: str,
    default: Optional[Path] = None,
) -> Path:
    """Let the user pick a previously-trained overseer directory."""
    dirs = list_trained_dirs(models_root, prefix)
    if default is None:
        default = dirs[-1] if dirs else None

    if not dirs:
        fallback = _prompt(
            f"No trained overseers with prefix '{prefix}' found. Enter a path",
            default=str(default) if default else None,
        )
        if not fallback:
            raise FileNotFoundError("No load directory provided.")
        return Path(fallback).expanduser().resolve()

    print("\nAvailable trained overseers:")
    for idx, path in enumerate(dirs, 1):
        marker = "  (default)" if default is not None and path == default else ""
        print(f"  [{idx}] {path.name}{marker}")

    response = _prompt(
        "Choose a trained overseer (# or path)",
        default=default.name if default else None,
    )
    if not response:
        if default is None:
            raise FileNotFoundError("No trained overseer selected.")
        return default
    if response.isdigit():
        pick = int(response)
        if 1 <= pick <= len(dirs):
            return dirs[pick - 1]
        raise ValueError(f"Trained overseer index out of range: {pick}")
    candidate = Path(response).expanduser()
    if not candidate.is_absolute():
        candidate = Path(models_root) / candidate
    return candidate.resolve()


def make_timestamped_dir(models_root: Path, prefix: str) -> Path:
    """Create and return ``<models_root>/<prefix>_YYYYmmdd_HHMMSS/``."""
    root = Path(models_root)
    root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = root / f"{prefix}_{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "experts").mkdir(parents=True, exist_ok=True)
    return out


# ---------------------------------------------------------------------------
# Manifest helpers (small JSON sidecar for every saved overseer).
# ---------------------------------------------------------------------------
def write_manifest(out_dir: Path, manifest: Dict[str, Any]) -> None:
    path = Path(out_dir) / "manifest.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, default=str)


def read_manifest(in_dir: Path) -> Dict[str, Any]:
    path = Path(in_dir) / "manifest.json"
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
