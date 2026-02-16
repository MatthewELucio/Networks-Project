#!/usr/bin/env python3
"""database_firebase.py

Firestore-backed database interface that mirrors database.py (SQLite).
Stores captures and flowlets in Firebase Cloud Firestore via firebase.py.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Type, TypeVar

# Allow importing firebase from repo root
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from firebase import ParsedFlowletFirestore, identity_flowlet_transform


@dataclass
class Capture:
    """Represents a packet capture file (mirrors database.Capture)."""
    id: Optional[str] = None  # Firestore document ID (set to file_path when added)
    file_path: Optional[str] = None
    created_at: Optional[datetime] = None
    status: str = "completed"
    llm_ip_map: Optional[str] = None  # JSON string of {ip: llm_name}
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "file_path": self.file_path,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "status": self.status,
            "llm_ip_map": json.loads(self.llm_ip_map) if self.llm_ip_map else {},
            "notes": self.notes,
        }


@dataclass
class Flowlet:
    """Represents a flowlet extracted from a capture (mirrors database.Flowlet)."""
    id: Optional[str] = None
    capture_id: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    flowlet_id: int = 0
    traffic_class: Optional[str] = None
    llm_name: Optional[str] = None
    outgoing: Optional[bool] = None
    direction_encoded: int = 0
    start_ts: float = 0.0
    end_ts: float = 0.0
    duration: float = 0.0
    packet_count: int = 0
    total_bytes: int = 0
    inter_packet_time_mean: Optional[float] = None
    inter_packet_time_std: Optional[float] = None
    packet_size_mean: Optional[float] = None
    packet_size_std: Optional[float] = None
    inter_packet_times: Optional[str] = None  # JSON array
    packet_sizes: Optional[str] = None       # JSON array
    model_llm_prediction: Optional[str] = None
    model_llm_confidence: Optional[float] = None
    ground_truth_llm: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict matching database.Flowlet.to_dict() for Firestore."""
        return {
            "id": self.id,
            "capture_id": self.capture_id,
            "flow_key": {
                "src_ip": self.src_ip,
                "src_port": self.src_port,
                "dst_ip": self.dst_ip,
                "dst_port": self.dst_port,
                "protocol": self.protocol,
            },
            "flowlet_id": self.flowlet_id,
            "traffic_class": self.traffic_class,
            "llm_name": self.llm_name,
            "outgoing": self.outgoing,
            "direction_encoded": self.direction_encoded,
            "start_ts": self.start_ts,
            "end_ts": self.end_ts,
            "duration": self.duration,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "inter_packet_time_mean": self.inter_packet_time_mean,
            "inter_packet_time_std": self.inter_packet_time_std,
            "packet_size_mean": self.packet_size_mean,
            "packet_size_std": self.packet_size_std,
            "inter_packet_times": json.loads(self.inter_packet_times) if self.inter_packet_times else [],
            "packet_sizes": json.loads(self.packet_sizes) if self.packet_sizes else [],
            "model_llm_prediction": self.model_llm_prediction,
            "model_llm_confidence": self.model_llm_confidence,
            "ground_truth_llm": self.ground_truth_llm,
        }


T = TypeVar("T", Capture, Flowlet)


class _Query:
    """Minimal query-like object for session.query(Capture).filter_by(...).first() and .get(id)."""
    def __init__(self, session: "FirebaseSession", model: Type[T]):
        self._session = session
        self._model = model
        self._filter_file_path: Optional[str] = None

    def filter_by(self, file_path: Optional[str] = None, **kwargs: Any) -> "_Query":
        if file_path is not None:
            self._filter_file_path = file_path
        return self

    def first(self) -> Optional[Capture]:
        if self._model is not Capture:
            return None
        doc_id = self._filter_file_path
        if doc_id is None:
            return None
        # Return in-memory capture if it's the one we're building (so updates apply on commit)
        cap = self._session._current_capture
        if cap and (cap.id == doc_id or cap.file_path == doc_id):
            return cap
        doc = self._session._client.get_capture_raw(doc_id)
        if doc is None:
            return None
        return _doc_to_capture(doc_id, doc)

    def get(self, id: str) -> Optional[Capture]:
        cap = self._session._current_capture
        if cap and (cap.id == id or cap.file_path == id):
            return cap
        doc = self._session._client.get_capture_raw(id)
        if doc is None:
            return None
        return _doc_to_capture(id, doc)


def _doc_to_capture(doc_id: str, doc: Dict[str, Any]) -> Capture:
    """Build a Capture from a Firestore document."""
    created = doc.get("created_at")
    if isinstance(created, str):
        try:
            created = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except Exception:
            created = None
    llm_map = doc.get("llm_ip_map")
    if isinstance(llm_map, dict):
        llm_map = json.dumps(llm_map)
    return Capture(
        id=doc_id,
        file_path=doc.get("file_path") or doc_id,
        created_at=created,
        status=doc.get("status", "completed"),
        llm_ip_map=llm_map,
        notes=doc.get("notes"),
    )


class FirebaseSession:
    """Session that buffers one capture and its flowlets, then writes to Firestore on commit."""

    def __init__(self, client: ParsedFlowletFirestore):
        self._client = client
        self._current_capture: Optional[Capture] = None
        self._flowlets_buf: List[Flowlet] = []

    def add(self, obj: Any) -> None:
        if isinstance(obj, Capture):
            self._current_capture = obj
            if obj.file_path and not obj.id:
                obj.id = obj.file_path
            if obj.created_at is None:
                obj.created_at = datetime.utcnow()
        elif isinstance(obj, Flowlet):
            self._flowlets_buf.append(obj)

    def flush(self) -> None:
        # No-op: capture.id is set in add(Capture)
        pass

    def commit(self) -> None:
        if not self._current_capture:
            return
        cap = self._current_capture
        capture_id = cap.id or cap.file_path
        if not capture_id:
            return
        extra = {
            "file_path": cap.file_path,
            "created_at": cap.created_at.isoformat() if cap.created_at else None,
            "status": cap.status,
            "llm_ip_map": cap.llm_ip_map,  # store as JSON string; firebase can write as-is
            "notes": cap.notes,
        }
        # Normalize llm_ip_map for Firestore: can be dict or JSON string
        if isinstance(extra.get("llm_ip_map"), str):
            try:
                extra["llm_ip_map"] = json.loads(extra["llm_ip_map"])
            except Exception:
                pass
        flowlet_dicts = [f.to_dict() for f in self._flowlets_buf]
        self._client.write_capture(
            capture_id=capture_id,
            flowlets=flowlet_dicts,
            overwrite=True,
            extra_metadata=extra,
        )
        self._current_capture = None
        self._flowlets_buf = []

    def query(self, model: Type[T]) -> _Query:
        return _Query(self, model)

    def close(self) -> None:
        self._current_capture = None
        self._flowlets_buf = []


_client: Optional[ParsedFlowletFirestore] = None


def init_database(db_path: Optional[str] = None) -> None:
    """Initialize the Firestore client. db_path is ignored (kept for API compatibility)."""
    global _client
    _client = ParsedFlowletFirestore(flowlet_transform=identity_flowlet_transform)


def get_db() -> Generator[FirebaseSession, None, None]:
    """Get a database session generator (e.g. for FastAPI Depends(get_db))."""
    if _client is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    session = FirebaseSession(_client)
    try:
        yield session
    finally:
        session.close()


def get_db_session() -> FirebaseSession:
    """Get a database session directly. Call session.close() when done."""
    if _client is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    return FirebaseSession(_client)


def close_db() -> None:
    """Close/release database client."""
    global _client
    _client = None
