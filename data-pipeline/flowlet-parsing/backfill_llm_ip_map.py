#!/usr/bin/env python3
"""Backfill `llm_ip_map` on selected capture documents.

This mirrors the final metadata update performed by `live_capture_to_db.py`:
the capture document is updated in place and `llm_ip_map` is stored as a JSON
string of `{ip: llm_name}` mappings.

By default this targets the three April 9 captures requested in the task:
`gavin_llm_april_9_0.05`, `gavin_llm_april_9_0.1`, and `gavin_llm_april_9_0.2`.

Usage:

    python3 data-pipeline/flowlet-parsing/backfill_llm_ip_map.py
    python3 data-pipeline/flowlet-parsing/backfill_llm_ip_map.py --dry-run

If a capture document is too large to update directly, the script removes
stored flowlets one by one and retries the metadata write until the mapping
fits.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Sequence, Tuple


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


DEFAULT_CAPTURE_IDS = [
    "gavin_llm_april_9_0.05",
    "gavin_llm_april_9_0.1",
    "gavin_llm_april_9_0.2",
]

CLAUDE_IPS = [
    "2001:558:feed::1",
    "2601:5cf:407e:8160:c544:5d5c:e953:f79",
    "2607:6bc0::10",
    "160.79.104.10",
]

GEMINI_IPS = [
    "142.250.31.101",
    "2607:f8b0:4004:c17::65",
    "142.251.16.139",
    "2607:f8b0:4004:c23::8a",
    "2001:558:feed::2",
    "2607:f8b0:4002:c2c::71",
    "64.233.185.139",
    "142.251.15.100",
    "2607:f8b0:4002:c2c::64",
    "2607:f8b0:4002:c2c::65",
    "172.217.215.138",
    "2607:f8b0:4002:c2c::8b",
    "142.250.9.100",
    "2607:f8b0:4002:c08::66",
    "173.194.219.101",
    "172.217.215.113",
    "2607:f8b0:4002:c2c::8a",
    "2607:f8b0:4002:c02::66",
    "142.251.15.139",
    "108.177.122.113",
    "2607:f8b0:4002:c11::8b",
    "142.251.15.138",
    "2607:f8b0:4002:c03::8b",
    "74.125.21.101",
    "142.251.15.102",
    "2607:f8b0:4002:c2c::66",
    "2607:f8b0:4002:c11::71",
    "142.250.9.138",
    "2607:f8b0:4002:c0f::8b",
    "64.233.177.102",
    "2607:f8b0:4002:c09::8a",
    "64.233.177.101",
    "2607:f8b0:4002:c09::71",
    "173.194.219.102",
    "2607:f8b0:4002:c0f::66",
    "74.125.21.138",
    "2607:f8b0:4002:c11::64",
    "2607:f8b0:4002:c06::8a",
    "64.233.185.138",
    "74.125.21.100",
    "2607:f8b0:4002:c06::8b",
    "142.250.9.102",
    "2607:f8b0:4002:c08::8a",
    "74.125.21.139",
    "2607:f8b0:4002:c06::64",
    "142.251.15.113",
    "2607:f8b0:4002:c03::66",
    "64.233.176.138",
    "2607:f8b0:4002:c09::8b",
    "108.177.122.101",
    "2607:f8b0:4002:c02::8b",
    "2607:f8b0:4002:c09::65",
    "2607:f8b0:4002:c0f::71",
    "172.217.215.139",
    "172.217.215.102",
    "64.233.185.101",
    "64.233.185.102",
    "142.251.15.101",
    "2607:f8b0:4002:c05::71",
    "2607:f8b0:4002:c06::65",
    "74.125.21.102",
    "2607:f8b0:4002:c05::66",
    "2607:f8b0:4002:c0f::8a",
    "2607:f8b0:4002:c11::66",
    "2607:f8b0:4002:c02::64",
    "173.194.219.138",
    "64.233.185.113",
    "2607:f8b0:4002:c03::64",
    "2607:f8b0:4002:c09::64",
    "2607:f8b0:4002:c09::66",
    "64.233.176.102",
]


def build_llm_ip_map() -> Dict[str, str]:
    """Build the deduplicated `{ip: llm_name}` map."""
    llm_ip_map: Dict[str, str] = {}
    for ip in CLAUDE_IPS:
        llm_ip_map[ip] = "CLAUDE"
    for ip in GEMINI_IPS:
        llm_ip_map[ip] = "GEMINI"
    return llm_ip_map


def load_backend(backend_name: str):
    """Import the requested database backend module."""
    if backend_name == "auto":
        for module_name in ("database_mongodb", "database_firebase", "database"):
            try:
                return __import__(module_name)
            except ImportError:
                continue
        raise RuntimeError("Could not import a database backend module.")

    if backend_name == "mongodb":
        import database_mongodb as backend

        return backend
    if backend_name == "firebase":
        import database_firebase as backend

        return backend
    if backend_name == "sqlite":
        import database as backend

        return backend
    raise ValueError(f"Unsupported backend: {backend_name}")


def resolve_capture_ids(raw_ids: Sequence[str] | None) -> List[str]:
    if raw_ids:
        capture_ids = [item.strip() for item in raw_ids if item.strip()]
    else:
        capture_ids = list(DEFAULT_CAPTURE_IDS)
    if len(capture_ids) != 3:
        raise ValueError("Expected exactly 3 capture IDs in threshold order: 0.05, 0.1, 0.2")
    return capture_ids


def update_capture_metadata(db_session, capture_cls, capture_id: str, llm_ip_map: Dict[str, str]) -> bool:
    """Write `llm_ip_map` to a single capture row/document."""
    capture = db_session.query(capture_cls).filter_by(file_path=capture_id).first()
    if capture is None:
        try:
            capture = db_session.query(capture_cls).get(capture_id)
        except Exception:
            capture = None
    if capture is None:
        return False

    capture.llm_ip_map = json.dumps(llm_ip_map)
    db_session.commit()
    return True


def is_oversized_document_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return any(
        token in message
        for token in (
            "too large",
            "document too large",
            "maximum bson object size",
            "bsonobj size",
            "request entity too large",
            "entity too large",
            "resulting document after update is larger than",
            "document after update is larger than",
            "exceeds the maximum size",
            "size limit",
        )
    )


def _mongo_backfill_capture(db_session, capture_id: str, llm_ip_map: Dict[str, str]) -> Tuple[bool, int]:
    collection = getattr(db_session, "_captures", None)
    if collection is None:
        return False, 0

    removed_flowlets = 0
    while True:
        try:
            result = collection.update_one(
                {"_id": capture_id},
                {"$set": {"llm_ip_map": llm_ip_map}},
                upsert=False,
            )
            return result.matched_count > 0, removed_flowlets
        except Exception as exc:
            if not is_oversized_document_error(exc):
                raise

        doc = collection.find_one({"_id": capture_id}, {"flowlets": 1})
        flowlets = doc.get("flowlets") if doc else None
        if not flowlets:
            return False, removed_flowlets

        collection.update_one({"_id": capture_id}, {"$pop": {"flowlets": 1}})
        removed_flowlets += 1


def _firestore_backfill_capture(db_session, capture_id: str, llm_ip_map: Dict[str, str]) -> Tuple[bool, int]:
    client = getattr(db_session, "_client", None)
    if client is None:
        return False, 0

    try:
        from google.cloud import firestore
    except Exception:
        return False, 0

    doc_ref = client.capture_ref(capture_id)
    removed_flowlets = 0

    while True:
        try:
            doc_ref.set({"llm_ip_map": llm_ip_map}, merge=True)
            return True, removed_flowlets
        except Exception as exc:
            if not is_oversized_document_error(exc):
                raise

        snap = doc_ref.get()
        doc = snap.to_dict() or {}
        flowlet_keys = sorted(
            key for key in doc.keys() if key.startswith("flowlet_") and isinstance(doc.get(key), dict)
        )
        if not flowlet_keys:
            return False, removed_flowlets

        doc_ref.set({flowlet_keys[-1]: firestore.DELETE_FIELD}, merge=True)
        removed_flowlets += 1


def backfill_capture(db_session, capture_cls, backend_name: str, capture_id: str, llm_ip_map: Dict[str, str]) -> Tuple[bool, int]:
    try:
        if update_capture_metadata(db_session, capture_cls, capture_id, llm_ip_map):
            return True, 0
    except Exception as exc:
        if not is_oversized_document_error(exc):
            raise

    if backend_name == "database_mongodb":
        return _mongo_backfill_capture(db_session, capture_id, llm_ip_map)
    if backend_name == "database_firebase":
        return _firestore_backfill_capture(db_session, capture_id, llm_ip_map)
    return False, 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Backfill llm_ip_map onto the April 9 capture documents.",
    )
    parser.add_argument(
        "--backend",
        choices=("auto", "mongodb", "firebase", "sqlite"),
        default="auto",
        help="Database backend to use. Auto prefers MongoDB, then Firestore, then SQLite.",
    )
    parser.add_argument(
        "--capture-id",
        nargs=3,
        metavar=("CAPTURE_0_05", "CAPTURE_0_1", "CAPTURE_0_2"),
        help="Optional override for the three capture IDs in threshold order.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the updates without writing them.",
    )
    args = parser.parse_args()

    backend = load_backend(args.backend)
    if backend.__name__ == "database":
        backend.init_database()
    else:
        backend.init_database(None)
    llm_ip_map = build_llm_ip_map()
    capture_ids = resolve_capture_ids(args.capture_id)

    db = backend.get_db_session()
    try:
        print(f"Backend: {args.backend}")
        print(f"Mappings: {len(llm_ip_map)} unique IPs")
        print(f"Captures: {capture_ids}")

        updated = 0
        for capture_id in capture_ids:
            if args.dry_run:
                print(f"[DRY-RUN] Would update {capture_id} with {len(llm_ip_map)} mappings")
                updated += 1
                continue

            try:
                success, removed = backfill_capture(db, backend.Capture, backend.__name__, capture_id, llm_ip_map)
            except Exception as exc:
                print(f"Failed to update {capture_id}: {exc}")
                continue

            if success:
                updated += 1
                if removed:
                    print(f"Updated {capture_id} after removing {removed} flowlets")
                else:
                    print(f"Updated {capture_id}")
            else:
                print(f"Capture not found: {capture_id}")

        print(f"Done. Updated {updated}/{len(capture_ids)} captures.")
    finally:
        try:
            db.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()