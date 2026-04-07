#!/usr/bin/env python3
"""Backfill missing capture.threshold values in MongoDB.

Rules:
- Only updates captures where `threshold` is absent or null.
- Extracts threshold from the numeric suffix of the capture title.
  Example: "matthew_capture_0.05" -> 0.05
- Uses `_id` first, then `file_path` as fallback title source.

By default this runs in dry-run mode and prints what would change.
Use --apply to persist updates.
"""
from __future__ import annotations

import argparse
import os
import re
from typing import Optional

from dotenv import load_dotenv
from pymongo import MongoClient


DEFAULT_DB_NAME = "networks_project"
DEFAULT_COLLECTION = "captures"
# Thresholds are encoded in capture titles like:
# - "foo_0.05"
# - "foo_0.1"
# - "foo_0.2"
# Some captures include an additional part suffix, e.g. "foo_0.1_part_1".
# Only these three thresholds are valid, so we match them explicitly.
_VALID_THRESHOLDS = (0.05, 0.1, 0.2)
_THRESHOLD_IN_TITLE_RE = re.compile(
    r"(?:^|[_\s])(0\.05|0\.1|0\.2)(?:$|[_\s])"
)


def extract_threshold_from_title(title: str) -> Optional[float]:
    if not title:
        return None
    # Prefer the *last* valid threshold occurrence in case the title contains
    # multiple numeric fields.
    matches = _THRESHOLD_IN_TITLE_RE.findall(str(title))
    if not matches:
        return None
    try:
        threshold = float(matches[-1])
    except ValueError:
        return None
    return threshold if threshold in _VALID_THRESHOLDS else None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Backfill missing threshold values in MongoDB captures.",
    )
    parser.add_argument("--uri", help="Mongo URI (defaults to MONGODB_URI from .env).")
    parser.add_argument("--db-name", default=DEFAULT_DB_NAME)
    parser.add_argument("--collection", default=DEFAULT_COLLECTION)
    parser.add_argument("--apply", action="store_true", help="Persist updates. Default is dry-run.")
    args = parser.parse_args()

    load_dotenv()
    uri = args.uri or os.getenv("MONGODB_URI")
    if not uri:
        raise RuntimeError("MONGODB_URI not set. Set it in .env or pass --uri.")

    client = MongoClient(uri)
    coll = client[args.db_name][args.collection]
    try:
        query = {"$or": [{"threshold": {"$exists": False}}, {"threshold": None}]}
        cursor = coll.find(query, {"_id": 1, "file_path": 1, "threshold": 1})

        inspected = 0
        candidates = 0
        updated = 0

        for doc in cursor:
            inspected += 1
            capture_id = str(doc.get("_id", ""))
            title = capture_id or str(doc.get("file_path", ""))
            threshold = extract_threshold_from_title(title)
            if threshold is None:
                continue
            candidates += 1
            if args.apply:
                result = coll.update_one({"_id": doc["_id"]}, {"$set": {"threshold": threshold}})
                updated += 1 if result.modified_count > 0 else 0

        mode = "APPLY" if args.apply else "DRY-RUN"
        print(f"[{mode}] Missing-threshold docs inspected: {inspected}")
        print(f"[{mode}] Backfillable docs found: {candidates}")
        if args.apply:
            print(f"[{mode}] Docs updated: {updated}")
    finally:
        client.close()


if __name__ == "__main__":
    main()

