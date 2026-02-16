#!/usr/bin/env python3
"""
firebase.py

Lightweight helper library for storing and retrieving parsed flowlets in
Google Cloud Firestore for the Networks Project.

Design goals
------------
- **Single file** with no dependencies on the rest of the codebase
  (you can import and use it from anywhere).
- **Explicit schema mapping** from the existing flowlet dictionaries /
  database rows into the new Cloud Firestore layout.
- **Safe, idempotent writes** with simple append / overwrite options.

Firestore layout
----------------
- Project ID: ``networks-project-s26``
- Database: default Cloud Firestore instance
- Collection: ``parsed-flowlets``
- One **document per capture**, where the document ID is a user-supplied
  string (e.g. capture file name).
- Each document contains capture metadata and one top-level field per flowlet:

    {
        "capture_id": "...",
        "file_path": "...",              # capture file path (from database.Capture)
        "created_at": "...",             # ISO datetime
        "status": "completed",
        "llm_ip_map": { ... },           # optional {ip: llm_name}
        "notes": null,
        "flowlet_000001": { ... },       # flowlet dict (schema below)
        "flowlet_000002": { ... },
        ...
    }

Field mapping
-------------
Two modes are supported:

**1. Full schema (database.py parity)**  
Use ``identity_flowlet_transform`` so each flowlet sub-document stores the same
fields as ``database.Flowlet.to_dict()``: ``capture_id``, ``flow_key``,
``flowlet_id``, ``traffic_class``, ``llm_name``, ``outgoing``,
``direction_encoded``, ``start_ts``, ``end_ts``, ``duration``,
``packet_count``, ``total_bytes``, ``inter_packet_time_mean/std``,
``packet_size_mean/std``, ``inter_packet_times``, ``packet_sizes``,
``model_llm_prediction``, ``model_llm_confidence``, ``ground_truth_llm``.
Used by ``data-pipeline/flowlet-parsing/database_firebase.py``.

**2. Default transform (legacy)**  
``_default_flowlet_transform``:
- Removes: ``traffic_class``, ``inter_packet_times``, ``packet_sizes``
- Adds: ``is_llm_prediction``, ``predicted_llm_name``, ``ground_truth_llm_name``

You can pass a custom ``flowlet_transform`` into ``ParsedFlowletFirestore``.

Dependencies
------------
This module requires ``google-cloud-firestore``:

    pip install google-cloud-firestore

Authentication is via the standard Google Application Default Credentials:
set environment variable ``GOOGLE_APPLICATION_CREDENTIALS`` to a service account JSON file, or
use any other ADC mechanism supported by the library.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from google.cloud import firestore

from dotenv import load_dotenv

# Load the environment variables
load_dotenv()


DEFAULT_PROJECT_ID = "networks-project-s26"
DEFAULT_COLLECTION = "parsed-flowlets"
REPO_ROOT = Path(__file__).resolve().parent


FlowletDict = Dict[str, Any]
TransformFn = Callable[[FlowletDict], FlowletDict]


def identity_flowlet_transform(flowlet: FlowletDict) -> FlowletDict:
    """
    No-op transform: store flowlet exactly as provided (full database.py schema).
    Use this when writing from database_firebase.py so Firestore matches database.Flowlet.
    """
    return dict(flowlet)


def _default_flowlet_transform(flowlet: FlowletDict) -> FlowletDict:
    """
    Transform a raw flowlet dict into the Firestore schema.

    - Keeps all existing keys except ``traffic_class``,
      ``inter_packet_times``, and ``packet_sizes``.
    - Adds:
        - ``is_llm_prediction`` (bool)
        - ``predicted_llm_name`` (str or None)
        - ``ground_truth_llm_name`` (str or None)

    The transformation is intentionally conservative:
    - If ``traffic_class`` is missing, ``is_llm_prediction`` is False.
    - If ``llm_name`` is missing, ``predicted_llm_name`` is None.
    - If ``ground_truth_llm`` is missing, ``ground_truth_llm_name`` is None.
    """
    # Work on a shallow copy so we don't mutate the caller's dict.
    out: FlowletDict = dict(flowlet)

    traffic_class = out.pop("traffic_class", None)
    # Drop detailed per-packet arrays to keep documents small.
    out.pop("inter_packet_times", None)
    out.pop("packet_sizes", None)

    # Store `source_file` relative to the repository root (directory containing this file),
    # when possible. If it cannot be relativized (e.g. different filesystem), keep as-is.
    source_file = out.get("source_file")
    if isinstance(source_file, str) and source_file:
        try:
            sf_path = Path(source_file).expanduser()
            # Avoid `.resolve()` here to keep this purely string-based; if the file
            # doesn't exist, `.resolve()` can still work but may be surprising.
            if sf_path.is_absolute():
                out["source_file"] = sf_path.relative_to(REPO_ROOT).as_posix()
            else:
                # Normalize separators for consistency.
                out["source_file"] = Path(os.fspath(sf_path)).as_posix()
        except Exception:
            pass
    llm_name = out.get("llm_name")
    ground_truth_llm = out.get("ground_truth_llm")

    is_llm = bool(traffic_class == "llm")

    out["is_llm_prediction"] = is_llm
    out["predicted_llm_name"] = llm_name
    out["ground_truth_llm_name"] = ground_truth_llm

    return out


def _next_flowlet_index(existing_fields: Mapping[str, Any]) -> int:
    """
    Compute the next numeric index for flowlet fields in a document.

    Flowlet fields are named ``flowlet_000001``, ``flowlet_000002``, etc.
    This function scans existing field names in the document and returns
    the next integer index (1‑based).
    """
    max_idx = 0
    prefix = "flowlet_"
    for key in existing_fields.keys():
        if not key.startswith(prefix):
            continue
        suffix = key[len(prefix) :]
        if suffix.isdigit():
            try:
                idx = int(suffix)
            except ValueError:
                continue
            max_idx = max(max_idx, idx)
    return max_idx + 1


def _format_flowlet_key(index: int) -> str:
    """Return the canonical field name for a flowlet index."""
    return f"flowlet_{index:06d}"


@dataclass
class ParsedFlowletFirestore:
    """
    High‑level helper for working with parsed flowlets in Firestore.

    Typical usage
    -------------
    >>> from firebase import ParsedFlowletFirestore
    >>> client = ParsedFlowletFirestore()
    >>> client.write_capture(
    ...     capture_id="capture_20251217_221914_0.0.0.0_0",
    ...     flowlets=flowlet_dicts,
    ...     overwrite=True,
    ... )
    """

    project_id: str = DEFAULT_PROJECT_ID
    collection_name: str = DEFAULT_COLLECTION
    flowlet_transform: TransformFn = _default_flowlet_transform

    def __post_init__(self) -> None:
        # Lazily create the Firestore client; this will use ADC.
        self._client = firestore.Client(project=self.project_id)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    @property
    def client(self) -> firestore.Client:
        """Expose the underlying Firestore client if direct access is needed."""
        return self._client

    def capture_ref(self, capture_id: str) -> firestore.DocumentReference:
        """
        Return a DocumentReference for a given capture ID.

        The capture ID is used directly as the Firestore document ID. It is up
        to the caller to choose something stable (e.g. the capture file name).
        """
        return self._client.collection(self.collection_name).document(capture_id)

    # -------------------------------
    # Write / update helper methods
    # -------------------------------
    def write_capture(
        self,
        capture_id: str,
        flowlets: Iterable[FlowletDict],
        overwrite: bool = True,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Write a complete capture document to Firestore.

        - If ``overwrite`` is True (default), any existing document for this
          capture ID is replaced.
        - If ``overwrite`` is False and the document already exists, flowlets
          are **appended** after the current max index.

        Args:
            capture_id: Identifier for this capture (used as document ID).
            flowlets: Iterable of flowlet dictionaries (from your parser or DB).
            overwrite: Whether to replace an existing document.
            extra_metadata: Optional dict of additional top‑level fields
                (e.g. {"capture_file": "...", "notes": "..."}).
        """
        doc_ref = self.capture_ref(capture_id)
        metadata = dict(extra_metadata or {})
        metadata.setdefault("capture_id", capture_id)

        if overwrite:
            payload = dict(metadata)
            for idx, flowlet in enumerate(flowlets, start=1):
                transformed = self.flowlet_transform(flowlet)
                key = _format_flowlet_key(idx)
                payload[key] = transformed
            doc_ref.set(payload)
            return

        # Append mode: fetch existing document and append new flowlets.
        snap = doc_ref.get()
        if snap.exists:
            existing = snap.to_dict() or {}
        else:
            existing = dict(metadata)

        next_idx = _next_flowlet_index(existing)
        updates: Dict[str, Any] = {}
        for flowlet in flowlets:
            transformed = self.flowlet_transform(flowlet)
            key = _format_flowlet_key(next_idx)
            updates[key] = transformed
            next_idx += 1

        # Also upsert any missing metadata keys (we will not overwrite them).
        for k, v in metadata.items():
            if k not in existing:
                updates[k] = v

        doc_ref.set(updates, merge=True)

    def append_flowlets(
        self,
        capture_id: str,
        flowlets: Iterable[FlowletDict],
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Convenience wrapper to append flowlets to an existing capture document.

        If the document does not exist, it will be created.
        """
        self.write_capture(
            capture_id=capture_id,
            flowlets=flowlets,
            overwrite=False,
            extra_metadata=extra_metadata,
        )

    # -------------------------------
    # Read helper methods
    # -------------------------------
    def get_capture_raw(self, capture_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch the raw Firestore document for a capture.

        Returns:
            A dictionary of the document fields, or None if the document
            does not exist.
        """
        doc_ref = self.capture_ref(capture_id)
        snap = doc_ref.get()
        if not snap.exists:
            return None
        return snap.to_dict()

    def list_flowlets(
        self,
        capture_id: str,
    ) -> List[Tuple[str, FlowletDict]]:
        """
        Return all flowlets for a capture as ``(field_name, flowlet_dict)`` pairs.

        This filters fields whose key starts with ``"flowlet_"`` and returns
        them sorted by index.
        """
        doc = self.get_capture_raw(capture_id)
        if doc is None:
            return []

        flowlet_items: List[Tuple[str, FlowletDict]] = []
        for key, value in doc.items():
            if not key.startswith("flowlet_"):
                continue
            if not isinstance(value, dict):
                continue
            flowlet_items.append((key, value))

        # Sort by numeric index embedded in the key
        flowlet_items.sort(key=lambda kv: kv[0])
        return flowlet_items

    def iter_captures(self) -> Iterable[Tuple[str, Dict[str, Any]]]:
        """
        Stream all capture documents in the collection.

        Yields:
            Tuples of (capture_id, document_dict).
        """
        for snap in self._client.collection(self.collection_name).stream():
            yield snap.id, snap.to_dict() or {}


__all__ = [
    "ParsedFlowletFirestore",
    "identity_flowlet_transform",
    "_default_flowlet_transform",
]

def main():
    """
    Confirms that the Firestore client is working and can reach the database.
    """
    import traceback
    try:
        client = ParsedFlowletFirestore()
        print("Firestore client created successfully")
        print(client.client)
        # google-cloud-firestore uses `collections()` (an iterator), not `list_collections()`.
        collection_ids = [c.id for c in client.client.collections()]
        print("Top-level collections:", collection_ids)
        print("Firestore client list collections successful")
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        print("Firestore client creation failed")

# def test_write_capture():
#     # parse the given capture file and get the flowlets
#     capture_id = "capture_20251217_221914_0.0.0.0_0.txt"
#     from pathlib import Path
#     file_path = Path(__file__).parent / 'captures' / capture_id
#     print(file_path)
#     import sys
#     sys.path.insert(0, str(Path(__file__).parent / "packet-analysis"))
#     from parse_flowlets_v2 import process_capture_file
#     flowlets, _ = process_capture_file(file_path, threshold=0.1, bidirectional=False, llm_ip_map={}, db_session=None, capture_id=capture_id)
#     client = ParsedFlowletFirestore()
#     client.write_capture(capture_id, flowlets)
#     print("Capture written successfully")

if __name__ == "__main__":
    main()