#!/usr/bin/env python3
"""db_snapshot.py

Download a local JSON snapshot of the cloud MongoDB capture database.

Features
--------
- Exports captures as JSON files on the local filesystem.
- Supports filtering by:
  - capture date range (created_at)
  - capture threshold range (top-level `threshold` field)
- Two usage modes:
  1) Interactive wizard when run with no CLI args.
  2) Non-interactive mode with CLI parameters.

Output layout
-------------
<output_dir>/
  manifest.json
  captures/
    <capture_id>.json
    ...
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from dotenv import load_dotenv
from pymongo import MongoClient


DEFAULT_DB_NAME = "networks_project"
DEFAULT_COLLECTION = "captures"


def _banner(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def _sanitize_filename(name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", name.strip())
    return safe[:180] if safe else "capture"


def _parse_iso_date(value: Optional[str]) -> Optional[str]:
    """Validate ISO-like date string; return normalized ISO string for comparisons."""
    if not value:
        return None
    v = value.strip()
    if not v:
        return None
    # Accept YYYY-MM-DD by expanding to midnight UTC-ish string.
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
        return f"{v}T00:00:00"
    # Validate datetime-like input.
    try:
        datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid date format: {value!r}. Use YYYY-MM-DD or ISO datetime.") from exc
    return v


def _parse_float(value: Optional[str], field_name: str) -> Optional[float]:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        return float(s)
    except ValueError as exc:
        raise ValueError(f"Invalid {field_name}: {value!r}. Must be numeric.") from exc


def _connect_client(uri: Optional[str] = None) -> MongoClient:
    load_dotenv()
    mongo_uri = uri or os.getenv("MONGODB_URI")
    if not mongo_uri:
        raise RuntimeError("MONGODB_URI not set. Add it to .env or pass --uri.")
    return MongoClient(mongo_uri)


def _build_query(
    start_date: Optional[str],
    end_date: Optional[str],
    threshold_min: Optional[float],
    threshold_max: Optional[float],
) -> Dict[str, Any]:
    query: Dict[str, Any] = {}

    if start_date or end_date:
        date_clause: Dict[str, Any] = {}
        if start_date:
            date_clause["$gte"] = start_date
        if end_date:
            date_clause["$lte"] = end_date
        query["created_at"] = date_clause

    # Threshold filtering with conversion to numeric when possible.
    # If threshold field is missing/non-convertible, it won't match threshold filters.
    if threshold_min is not None or threshold_max is not None:
        threshold_exprs = []
        if threshold_min is not None:
            threshold_exprs.append(
                {
                    "$gte": [
                        {"$convert": {"input": "$threshold", "to": "double", "onError": None, "onNull": None}},
                        threshold_min,
                    ]
                }
            )
        if threshold_max is not None:
            threshold_exprs.append(
                {
                    "$lte": [
                        {"$convert": {"input": "$threshold", "to": "double", "onError": None, "onNull": None}},
                        threshold_max,
                    ]
                }
            )
        if threshold_exprs:
            query["$expr"] = {"$and": threshold_exprs}

    return query


def _interactive_inputs() -> argparse.Namespace:
    _banner("DB Snapshot Wizard")
    print("Press Enter to accept defaults.\n")

    default_out = Path("data/snapshots") / f"snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    output_dir = input(f"Output directory [{default_out.expanduser().resolve()}]: ").strip() or str(default_out)

    start_raw = input("Start date (YYYY-MM-DD or ISO, optional): ").strip() or None
    end_raw = input("End date (YYYY-MM-DD or ISO, optional): ").strip() or None
    thr_min_raw = input("Minimum threshold (optional): ").strip() or None
    thr_max_raw = input("Maximum threshold (optional): ").strip() or None

    db_name = input(f"Mongo DB name [{DEFAULT_DB_NAME}]: ").strip() or DEFAULT_DB_NAME
    collection = input(f"Collection name [{DEFAULT_COLLECTION}]: ").strip() or DEFAULT_COLLECTION

    return argparse.Namespace(
        output_dir=output_dir,
        start_date=start_raw,
        end_date=end_raw,
        threshold_min=thr_min_raw,
        threshold_max=thr_max_raw,
        db_name=db_name,
        collection=collection,
        uri=None,
        yes=False,
    )


def _coerce_args(args: argparse.Namespace) -> argparse.Namespace:
    args.start_date = _parse_iso_date(args.start_date)
    args.end_date = _parse_iso_date(args.end_date)
    args.threshold_min = _parse_float(args.threshold_min, "threshold_min")
    args.threshold_max = _parse_float(args.threshold_max, "threshold_max")
    return args


def _confirm_plan(args: argparse.Namespace, query: Dict[str, Any]) -> bool:
    _banner("Snapshot Plan")
    output_abs = Path(args.output_dir).expanduser().resolve()
    print(f"Output directory: {output_abs}")
    print(f"Database:         {args.db_name}")
    print(f"Collection:       {args.collection}")
    print(f"Query filter:     {json.dumps(query, indent=2)}")
    if args.yes:
        return True
    ans = input("\nProceed? [y/N]: ").strip().lower()
    return ans in {"y", "yes"}


def create_snapshot(args: argparse.Namespace) -> None:
    out_dir = Path(args.output_dir).expanduser().resolve()
    captures_dir = out_dir / "captures"
    captures_dir.mkdir(parents=True, exist_ok=True)

    query = _build_query(
        start_date=args.start_date,
        end_date=args.end_date,
        threshold_min=args.threshold_min,
        threshold_max=args.threshold_max,
    )

    if not _confirm_plan(args, query):
        print("Cancelled.")
        return

    client = _connect_client(args.uri)
    try:
        coll = client[args.db_name][args.collection]
        cursor = coll.find(query, no_cursor_timeout=True)

        total = 0
        for doc in cursor:
            capture_id = str(doc.get("_id", f"capture_{total+1}"))
            filename = _sanitize_filename(capture_id) + ".json"
            target = captures_dir / filename
            with target.open("w", encoding="utf-8") as f:
                json.dump(doc, f, indent=2, default=str)
            total += 1
            if total % 100 == 0:
                print(f"Saved {total} captures...")

        manifest = {
            "created_at": datetime.utcnow().isoformat() + "Z",
            "db_name": args.db_name,
            "collection": args.collection,
            "query": query,
            "captures_exported": total,
            "captures_dir": str(captures_dir),
        }
        with (out_dir / "manifest.json").open("w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        _banner("Snapshot Complete")
        print(f"Captures exported: {total}")
        print(f"Output path:       {out_dir}")
        print("Files:")
        print(f"  - {out_dir / 'manifest.json'}")
        print(f"  - {captures_dir}/*.json")
    finally:
        client.close()


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Download a JSON snapshot of MongoDB captures with optional filters.",
    )
    p.add_argument("--output-dir", help="Directory to write snapshot files.")
    p.add_argument("--start-date", help="Inclusive start date (YYYY-MM-DD or ISO datetime).")
    p.add_argument("--end-date", help="Inclusive end date (YYYY-MM-DD or ISO datetime).")
    p.add_argument("--threshold-min", help="Minimum capture threshold (numeric).")
    p.add_argument("--threshold-max", help="Maximum capture threshold (numeric).")
    p.add_argument("--db-name", default=DEFAULT_DB_NAME, help=f"Mongo database name (default: {DEFAULT_DB_NAME}).")
    p.add_argument(
        "--collection",
        default=DEFAULT_COLLECTION,
        help=f"Mongo collection name (default: {DEFAULT_COLLECTION}).",
    )
    p.add_argument("--uri", help="MongoDB URI override (otherwise uses MONGODB_URI).")
    p.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt.")
    return p


def main() -> None:
    parser = _build_parser()

    # No parameters -> interactive wizard.
    if len(sys.argv) == 1:
        args = _interactive_inputs()
    else:
        args = parser.parse_args()
        if not args.output_dir:
            default_out = Path("data/snapshots") / f"snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            args.output_dir = str(default_out)

    try:
        args = _coerce_args(args)
    except ValueError as exc:
        print(f"Input error: {exc}")
        sys.exit(2)

    if args.threshold_min is not None and args.threshold_max is not None:
        if args.threshold_min > args.threshold_max:
            print("Input error: threshold_min cannot be greater than threshold_max.")
            sys.exit(2)

    create_snapshot(args)


if __name__ == "__main__":
    main()

