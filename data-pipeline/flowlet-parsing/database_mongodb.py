#!/usr/bin/env python3
"""database_mongodb.py

MongoDB-backed database interface that mirrors `database.py` / `database_firebase.py`.

Connection instructions
-----------------------
- This module expects a MongoDB instance reachable over the internet
- Install the driver:

    pip install pymongo

- Provide a connection URI via one of:
    1. Environment variable ``MONGODB_URI`` (recommended), e.g.:

        MONGODB_URI="mongodb+srv://user:pass@host.example.com/networks_project"

    2. Or pass it directly to ``init_database(uri)``.

- By default this module uses:
    - Database name: ``networks_project``
    - Collection: ``captures``

Each capture is stored as a single document:

    {
        _id: "<capture_id>",        # usually the capture's file_path
        file_path: "...",
        created_at: "<ISO string>",
        status: "active" | "completed" | "failed",
        llm_ip_map: { ip: llm_name, ... } | null,
        notes: "...",
        flowlets: [                  # list of flowlet dicts
            {
                "capture_id": "...",
                "flow_key": {...},
                "flowlet_id": 1,
                "traffic_class": "llm" | "non_llm",
                "llm_name": "...",
                "outgoing": true | false | null,
                "direction_encoded": 1 | -1 | 0,
                "start_ts": ...,
                "end_ts": ...,
                "duration": ...,
                "packet_count": ...,
                "total_bytes": ...,
                "inter_packet_time_mean": ...,
                "inter_packet_time_std": ...,
                "packet_size_mean": ...,
                "packet_size_std": ...,
                "inter_packet_times": [],   # long arrays may be omitted by writers
                "packet_sizes": [],
                "model_llm_prediction": "...",
                "model_llm_confidence": ...,
                "ground_truth_llm": "...",  # optional
            },
            ...
        ],
    }

API compatibility
-----------------
- Provides ``Capture`` and ``Flowlet`` dataclasses compatible with existing code.
- Provides a ``MongoSession`` with the same surface as ``FirebaseSession``:
  ``add()``, ``flush()``, ``commit()``, ``query()``, ``close()``.
- Provides top-level helpers:
  ``init_database()``, ``get_db()``, ``get_db_session()``, ``close_db()``.

You can swap this module for ``database_firebase.py`` in code such as
``live_capture_to_db.py`` by importing it as the backend module with
``Capture``, ``Flowlet``, ``init_database``, and ``get_db_session``.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Type, TypeVar

from dotenv import load_dotenv
from pymongo import MongoClient, UpdateOne


# Load environment variables so MONGODB_URI can be read from a .env file
load_dotenv()

# Reuses the same dataclass shapes as database_firebase for maximum compatibility


@dataclass
class Capture:
    """Represents a packet capture file (mirrors database.Capture)."""

    id: Optional[str] = None  # MongoDB document _id (set to file_path when added)
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
    inter_packet_times: Optional[str] = None  # JSON array (writers may omit to save space)
    packet_sizes: Optional[str] = None       # JSON array
    model_llm_prediction: Optional[str] = None
    model_llm_confidence: Optional[float] = None
    ground_truth_llm: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dict similar to database_firebase.Flowlet.to_dict()."""
        # For Mongo we default to empty arrays for the long sequences; callers may
        # still include them explicitly via inter_packet_times/packet_sizes if needed.
        flowlet_uuid = self.id or f"{self.capture_id}_{self.flowlet_id}_{self.src_ip}_{self.src_port}"
        
        return {
            "id": flowlet_uuid,
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
            "model_llm_prediction": self.model_llm_prediction,
            "model_llm_confidence": self.model_llm_confidence,
            "ground_truth_llm": self.ground_truth_llm,
        }


T = TypeVar("T", Capture, Flowlet)


class _Query:
    """Minimal query-like object for session.query(Capture).filter_by(...).first() and .get(id)."""

    def __init__(self, session: "MongoSession", model: Type[T]):
        self._session = session
        self._model = model
        self._filter_file_path: Optional[str] = None

    def filter_by(self, file_path: Optional[str] = None, **_: Any) -> "_Query":
        if file_path is not None:
            self._filter_file_path = file_path
        return self

    def first(self) -> Optional[Capture]:
        if self._model is not Capture:
            return None
        file_path = self._filter_file_path
        if file_path is None:
            return None
        # Prefer matching by _id (capture_id) which we set to file_path
        doc = self._session._captures.find_one({"_id": file_path})
        if doc is None:
            return None
        cap = _doc_to_capture_from_mongo(doc)
        self._session._current_capture = cap
        self._session._capture_doc_written = True
        return cap

    def get(self, id: str) -> Optional[Capture]:
        # Try in-memory first
        cap = self._session._current_capture
        if cap and (cap.id == id or cap.file_path == id):
            return cap
        doc = self._session._captures.find_one({"_id": id})
        if doc is None:
            return None
        cap = _doc_to_capture_from_mongo(doc)
        self._session._current_capture = cap
        self._session._capture_doc_written = True
        return cap


def _doc_to_capture_from_mongo(doc: Dict[str, Any]) -> Capture:
    """Build a Capture from a MongoDB document."""
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
        id=str(doc.get("_id")),
        file_path=doc.get("file_path") or str(doc.get("_id")),
        created_at=created,
        status=doc.get("status", "completed"),
        llm_ip_map=llm_map,
        notes=doc.get("notes"),
    )


class MongoSession:
    """Session that buffers one capture and its flowlets, then writes to MongoDB on commit.

    Supports streaming usage:

        add(Capture)
        add(Flowlet)
        commit()      # inserts or appends
        add(Flowlet)
        commit()
        ...

    and metadata-only updates:

        capture = session.query(Capture).get(capture_id)
        capture.status = "completed"
        session.commit()
    """

    def __init__(self, client: MongoClient, db_name: str, collection: str) -> None:
        self._client = client
        self._db = client[db_name]
        self._captures = self._db[collection]
        self._current_capture: Optional[Capture] = None
        self._flowlets_buf: List[Flowlet] = []
        self._capture_doc_written: bool = False

    def add(self, obj: Any) -> None:
        if isinstance(obj, Capture):
            self._current_capture = obj
            self._capture_doc_written = False
            if obj.file_path and not obj.id:
                obj.id = obj.file_path
            if obj.created_at is None:
                obj.created_at = datetime.utcnow()
        elif isinstance(obj, Flowlet):
            self._flowlets_buf.append(obj)

    def flush(self) -> None:
        # No-op; kept for API compatibility.
        pass

    def _capture_metadata(self, cap: Capture) -> Dict[str, Any]:
        llm = cap.llm_ip_map
        if isinstance(llm, str):
            try:
                llm = json.loads(llm)
            except Exception:
                llm = None
        return {
            "file_path": cap.file_path,
            "created_at": cap.created_at.isoformat() if cap.created_at else None,
            "status": cap.status,
            "llm_ip_map": llm,
            "notes": cap.notes,
        }

    def commit(self) -> None:
        if not self._current_capture:
            return
        cap = self._current_capture
        capture_id = cap.id or cap.file_path
        if not capture_id:
            return

        metadata = self._capture_metadata(cap)

        if self._flowlets_buf:
            flowlet_dicts = [f.to_dict() for f in self._flowlets_buf]
            if not self._capture_doc_written:
                doc = {
                    "_id": capture_id,
                    **metadata,
                    "flowlets": flowlet_dicts,
                }
                self._captures.replace_one({"_id": capture_id}, doc, upsert=True)
                self._capture_doc_written = True
            else:
                # Append new flowlets and update metadata
                self._captures.update_one(
                    {"_id": capture_id},
                    {
                        "$set": metadata,
                        "$push": {"flowlets": {"$each": flowlet_dicts}},
                    },
                    upsert=True,
                )
            self._flowlets_buf = []
            return

        # Metadata-only commit
        if not self._capture_doc_written:
            doc = {"_id": capture_id, **metadata, "flowlets": []}
            self._captures.replace_one({"_id": capture_id}, doc, upsert=True)
            self._capture_doc_written = True
        else:
            self._captures.update_one({"_id": capture_id}, {"$set": metadata}, upsert=True)

    def query(self, model: Type[T]) -> _Query:
        return _Query(self, model)

    def close(self) -> None:
        self._current_capture = None
        self._flowlets_buf = []
        self._capture_doc_written = False


_client: Optional[MongoClient] = None
_db_name: str = "networks_project"
_collection_name: str = "captures"


def init_database(uri: Optional[str] = None, db_name: str = "networks_project", collection: str = "captures") -> None:
    """Initialize the MongoDB client.

    Args:
        uri: Optional MongoDB URI. If not provided, uses the ``MONGODB_URI``
             environment variable. Example:
             ``mongodb+srv://user:pass@host.example.com/networks_project``.
        db_name: Name of the MongoDB database (default: ``networks_project``).
        collection: Name of the captures collection (default: ``captures``).
    """
    global _client, _db_name, _collection_name
    uri = uri or os.getenv("MONGODB_URI")
    if not uri:
        raise RuntimeError("MongoDB URI not provided. Set MONGODB_URI or pass uri to init_database().")
    _client = MongoClient(uri)
    _db_name = db_name
    _collection_name = collection


def get_db() -> Generator[MongoSession, None, None]:
    """Get a MongoDB session generator (FastAPI-compatible dependency style)."""
    if _client is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    session = MongoSession(_client, _db_name, _collection_name)
    try:
        yield session
    finally:
        session.close()


def get_db_session() -> MongoSession:
    """Get a MongoDB session directly. Call session.close() when done."""
    if _client is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    return MongoSession(_client, _db_name, _collection_name)


def close_db() -> None:
    """Close/release MongoDB client."""
    global _client
    if _client is not None:
        _client.close()
    _client = None


def main() -> None:
    """Simple CLI to test MongoDB connectivity over the internet.

    Usage:
        python database_mongodb.py

    Relies on ``MONGODB_URI`` unless a URI is hard-coded into this script.
    Prints basic connection info and lists the first few capture IDs.
    """
    uri = os.getenv("MONGODB_URI")
    if not uri:
        print("MONGODB_URI is not set. Please export it before running this test.")
        return

    try:
        init_database(uri=uri)
        session = get_db_session()
        db = session._db  # type: ignore[attr-defined]
        print(f"Connected to MongoDB database: {db.name}")
        print(f"Captures collection: {session._captures.full_name}")  # type: ignore[attr-defined]

        # List a few capture IDs (document _id values)
        print("Listing up to 5 captures (document _id):")
        for doc in session._captures.find({}, {"_id": 1}).limit(5):  # type: ignore[attr-defined]
            print(f" - {doc.get('_id')}")
        session.close()
        close_db()
        print("MongoDB connectivity test succeeded.")
    except Exception as exc:
        print("MongoDB connectivity test FAILED.")
        print(repr(exc))


if __name__ == "__main__":
    main()

