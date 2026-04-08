#!/usr/bin/env python3
"""db_stats.py

Print high-level statistics about the MongoDB backend without downloading
all documents. It reports:

- Number of captures (documents) in the captures collection.
- Average flowlets per capture.
- Total data size (as reported by MongoDB).

Connection:
- Uses the same settings as ``database_mongodb.py``:
  - Mongo URI from ``MONGODB_URI`` in your environment or ``.env`` file.
  - Database name: ``networks_project`` (by default).
  - Collection name: ``captures``.

Usage:
    cd data-pipeline
    python db_stats.py
"""
from __future__ import annotations

import os
from typing import Any, Dict

from dotenv import load_dotenv
from pymongo import MongoClient


DEFAULT_DB_NAME = "networks_project"
CAPTURES_COLLECTION = "captures"


def get_mongo_client() -> MongoClient:
    """Create a MongoClient using MONGODB_URI (from env or .env)."""
    load_dotenv()
    uri = os.getenv("MONGODB_URI")
    if not uri:
        raise RuntimeError(
            "MONGODB_URI is not set. Add it to your .env or export it in the shell."
        )
    return MongoClient(uri)


def compute_stats(client: MongoClient, db_name: str = DEFAULT_DB_NAME) -> Dict[str, Any]:
    """Compute capture count, average flowlets per capture, and total data size."""
    db = client[db_name]
    coll = db[CAPTURES_COLLECTION]

    # Number of capture documents
    capture_count = coll.estimated_document_count()

    # Average flowlets per capture: use aggregation to avoid pulling all docs
    avg_flowlets = 0.0
    if capture_count > 0:
        pipeline = [
            {
                "$group": {
                    "_id": None,
                    "total_flowlets": {
                        "$sum": {
                            "$cond": [
                                {"$isArray": "$flowlets"},
                                {"$size": "$flowlets"},
                                0,
                            ]
                        }
                    },
                }
            }
        ]
        agg = list(coll.aggregate(pipeline))
        if agg:
            total_flowlets = agg[0].get("total_flowlets", 0)
            avg_flowlets = total_flowlets / float(capture_count)

    # Total data size from $collStats (server-side)
    stats_pipeline = [
        {"$collStats": {"storageStats": {}}},
        {"$project": {"storageStats": 1, "_id": 0}},
    ]
    storage_result = list(coll.aggregate(stats_pipeline))
    total_size_bytes = None
    if storage_result:
        storage_stats = storage_result[0].get("storageStats", {})
        # Prefer "size" (logical data size in bytes) if present; fallback to "storageSize"
        total_size_bytes = storage_stats.get("size") or storage_stats.get("storageSize")

    return {
        "capture_count": capture_count,
        "avg_flowlets_per_capture": avg_flowlets,
        "total_size_bytes": total_size_bytes,
    }


def format_bytes(num: int) -> str:
    """Human-readable bytes."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num < 1024.0:
            return f"{num:3.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


def main() -> None:
    try:
        client = get_mongo_client()
    except Exception as exc:
        print(f"Failed to create Mongo client: {exc}")
        return

    try:
        stats = compute_stats(client)
    except Exception as exc:
        print("Error while querying MongoDB for stats.")
        print(repr(exc))
        return
    finally:
        client.close()

    capture_count = stats["capture_count"]
    avg_flowlets = stats["avg_flowlets_per_capture"]
    total_size_bytes = stats["total_size_bytes"]

    print("MongoDB capture statistics")
    print("--------------------------")
    print(f"Captures (documents): {capture_count}")
    print(f"Average flowlets per capture: {avg_flowlets:.2f}")
    if isinstance(total_size_bytes, (int, float)):
        print(f"Total data size (collection): {format_bytes(int(total_size_bytes))}")
    else:
        print("Total data size (collection): unavailable")


if __name__ == "__main__":
    main()

