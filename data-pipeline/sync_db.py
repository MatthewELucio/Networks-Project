#!/usr/bin/env python3
"""sync_db.py

Bidirectional sync between local SQLite (flowlet-parsing/database.py) and
Firebase Cloud Firestore (firebase.py). Only adds missing data; nothing is removed.

Schema: Matches live_capture_to_db / database_firebase. Flowlet fields include
flow_key, flowlet_id, traffic_class, llm_name, direction_encoded, timing, packet
stats, inter_packet_times/packet_sizes (JSON), model_llm_prediction/confidence.
Firebase docs may include ground_truth_llm; SQLite Flowlet does not (omitted on
write to local).

- Captures present only in SQLite → added to Firebase (with all their flowlets).
- Captures present only in Firebase → added to SQLite (with all their flowlets).
- Captures present in both are left unchanged (no flowlet-level merge).

Usage:
  python sync_db.py [--db-path PATH] [--preview] [--yes]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Paths so we can import flowlet-parsing and firebase
_DATA_PIPELINE = Path(__file__).resolve().parent
_FLOWLET_PARSING = _DATA_PIPELINE / "flowlet-parsing"
_REPO_ROOT = _DATA_PIPELINE.parent
for _p in (_FLOWLET_PARSING, _REPO_ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

try:
    from database import (
        init_database as init_local,
        get_db_session as get_local_session,
        Capture as LocalCapture,
        Flowlet as LocalFlowlet,
    )
except ImportError as e:
    sys.exit(f"Cannot import local database: {e}")

try:
    from firebase import ParsedFlowletFirestore, identity_flowlet_transform
except ImportError as e:
    sys.exit(f"Cannot import Firebase: {e}")


def _float_or_none(x: Any) -> Optional[float]:
    """Coerce to float for SQLite columns; leave None as None."""
    if x is None:
        return None
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _local_capture_key(cap: LocalCapture) -> str:
    """Stable key for matching captures (local uses file_path)."""
    return (cap.file_path or "").strip() or f"local_id_{cap.id}"


def load_local_captures_and_flowlets(
    db_path: str,
) -> Tuple[Dict[str, LocalCapture], Dict[str, List[Dict[str, Any]]]]:
    """Load all captures from SQLite keyed by file_path; each value has list of flowlet dicts."""
    init_local(db_path)
    session = get_local_session()
    try:
        captures = {_local_capture_key(c): c for c in session.query(LocalCapture).all()}
        flowlets_by_capture: Dict[str, List[Dict[str, Any]]] = {}
        for cap in captures.values():
            key = _local_capture_key(cap)
            flowlets = session.query(LocalFlowlet).filter_by(capture_id=cap.id).all()
            # Dict suitable for Firebase: capture_id as string (file_path)
            lst = []
            for f in flowlets:
                d = f.to_dict()
                d["capture_id"] = cap.file_path or str(cap.id)
                lst.append(d)
            flowlets_by_capture[key] = lst
        return captures, flowlets_by_capture
    finally:
        session.close()


def load_firebase_captures_and_flowlets(
    client: ParsedFlowletFirestore,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    """Load all capture docs from Firebase; return doc metadata and flowlet dicts per capture_id."""
    captures: Dict[str, Dict[str, Any]] = {}
    flowlets_by_capture: Dict[str, List[Dict[str, Any]]] = {}
    for capture_id, doc in client.iter_captures():
        key = (capture_id or "").strip()
        if not key:
            continue
        captures[key] = doc
        flowlet_list = client.list_flowlets(capture_id)
        flowlets_by_capture[key] = [v for _k, v in flowlet_list]
    return captures, flowlets_by_capture


def firebase_metadata_from_local_capture(cap: LocalCapture) -> Dict[str, Any]:
    """Build extra_metadata for Firebase write_capture from a SQLite Capture."""
    llm = cap.llm_ip_map
    if isinstance(llm, str):
        try:
            llm = json.loads(llm)
        except Exception:
            llm = {}
    return {
        "capture_id": cap.file_path or str(cap.id),
        "file_path": cap.file_path,
        "created_at": cap.created_at.isoformat() if cap.created_at else None,
        "status": cap.status or "completed",
        "llm_ip_map": llm,
        "notes": cap.notes,
    }


def write_local_capture_and_flowlets(
    session: Any,
    capture_id: str,
    doc: Dict[str, Any],
    flowlet_dicts: List[Dict[str, Any]],
) -> None:
    """Insert one capture and its flowlets into SQLite from Firebase doc + flowlet list."""
    file_path = capture_id
    created_at = doc.get("created_at")
    if isinstance(created_at, str):
        try:
            from datetime import datetime
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        except Exception:
            created_at = None
    llm_ip_map = doc.get("llm_ip_map")
    if isinstance(llm_ip_map, dict):
        llm_ip_map = json.dumps(llm_ip_map)
    cap = LocalCapture(
        file_path=file_path,
        created_at=created_at,
        status=doc.get("status", "completed"),
        llm_ip_map=llm_ip_map,
        notes=doc.get("notes"),
    )
    session.add(cap)
    session.flush()
    for d in flowlet_dicts:
        fk = d.get("flow_key") or {}
        ipt = d.get("inter_packet_times")
        ps = d.get("packet_sizes")
        if isinstance(ipt, list):
            ipt = json.dumps(ipt)
        if isinstance(ps, list):
            ps = json.dumps(ps)
        # Local (SQLite) Flowlet schema: no ground_truth_llm column; optional model_llm_*.
        flowlet = LocalFlowlet(
            capture_id=cap.id,
            src_ip=fk.get("src_ip"),
            src_port=int(fk.get("src_port")) if fk.get("src_port") is not None else None,
            dst_ip=fk.get("dst_ip"),
            dst_port=int(fk.get("dst_port")) if fk.get("dst_port") is not None else None,
            protocol=fk.get("protocol"),
            flowlet_id=int(d.get("flowlet_id", 0)),
            traffic_class=d.get("traffic_class"),
            llm_name=d.get("llm_name"),
            outgoing=d.get("outgoing"),
            direction_encoded=int(d.get("direction_encoded", 0)),
            start_ts=float(d.get("start_ts", 0)),
            end_ts=float(d.get("end_ts", 0)),
            duration=float(d.get("duration", 0)),
            packet_count=int(d.get("packet_count", 0)),
            total_bytes=int(d.get("total_bytes", 0)),
            inter_packet_time_mean=_float_or_none(d.get("inter_packet_time_mean")),
            inter_packet_time_std=_float_or_none(d.get("inter_packet_time_std")),
            packet_size_mean=_float_or_none(d.get("packet_size_mean")),
            packet_size_std=_float_or_none(d.get("packet_size_std")),
            inter_packet_times=ipt,
            packet_sizes=ps,
            model_llm_prediction=d.get("model_llm_prediction"),
            model_llm_confidence=_float_or_none(d.get("model_llm_confidence")),
        )
        session.add(flowlet)
    session.commit()


def run_sync(
    db_path: str,
    preview_only: bool = False,
    skip_confirm: bool = False,
) -> None:
    client = ParsedFlowletFirestore(flowlet_transform=identity_flowlet_transform)
    local_captures, local_flowlets = load_local_captures_and_flowlets(db_path)
    firebase_captures, firebase_flowlets = load_firebase_captures_and_flowlets(client)

    local_keys = set(local_captures.keys())
    firebase_keys = set(firebase_captures.keys())

    to_firebase = local_keys - firebase_keys
    to_local = firebase_keys - local_keys

    add_to_firebase_captures = len(to_firebase)
    add_to_firebase_flowlets = sum(len(local_flowlets.get(k, [])) for k in to_firebase)
    add_to_local_captures = len(to_local)
    add_to_local_flowlets = sum(len(firebase_flowlets.get(k, [])) for k in to_local)

    # Preview
    print("Sync preview (add-only; no data removed)")
    print("-" * 50)
    print("  → To Firebase (Cloud):")
    print(f"      {add_to_firebase_captures} capture(s), {add_to_firebase_flowlets} flowlet(s)")
    print("  → To Local (SQLite):")
    print(f"      {add_to_local_captures} capture(s), {add_to_local_flowlets} flowlet(s)")
    print("-" * 50)
    if add_to_firebase_captures == 0 and add_to_local_captures == 0:
        print("Nothing to sync.")
        return

    if preview_only:
        print("Preview only (use without --preview to apply).")
        return

    if not skip_confirm:
        try:
            reply = input("Proceed with sync? [y/N] ").strip().lower()
        except EOFError:
            reply = "n"
        if reply not in ("y", "yes"):
            print("Aborted.")
            return

    # Apply: add to Firebase
    for key in sorted(to_firebase):
        cap = local_captures[key]
        flowlet_dicts = local_flowlets.get(key, [])
        capture_id = cap.file_path or str(cap.id)
        metadata = firebase_metadata_from_local_capture(cap)
        client.write_capture(
            capture_id=capture_id,
            flowlets=flowlet_dicts,
            overwrite=True,
            extra_metadata=metadata,
        )
        print(f"  Added to Firebase: {capture_id} ({len(flowlet_dicts)} flowlets)")

    # Apply: add to SQLite
    if to_local:
        session = get_local_session()
        try:
            for key in sorted(to_local):
                doc = firebase_captures[key]
                flowlet_dicts = firebase_flowlets.get(key, [])
                write_local_capture_and_flowlets(session, key, doc, flowlet_dicts)
                print(f"  Added to SQLite: {key} ({len(flowlet_dicts)} flowlets)")
        finally:
            session.close()

    print("Sync complete.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sync missing captures/flowlets between local SQLite and Firebase (add-only).",
    )
    parser.add_argument(
        "--db-path",
        default="data/networks_project.db",
        help="Path to local SQLite database (default: data/networks_project.db).",
    )
    parser.add_argument(
        "--preview",
        action="store_true",
        help="Only show what would be added; do not ask or write.",
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip confirmation prompt and apply sync.",
    )
    args = parser.parse_args()
    run_sync(db_path=args.db_path, preview_only=args.preview, skip_confirm=args.yes)


if __name__ == "__main__":
    main()
