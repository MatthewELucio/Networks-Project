#!/usr/bin/env python3
"""Build a single flowlet feature JSON from snapshot capture documents.

Input layout:
  <snapshot_dir>/captures/*.json

Each capture JSON is expected to include a top-level "flowlets" list.

Output:
  <snapshot_dir>/<output_name>.json

The script also annotates each flowlet with source_file to support
incoming-model filters in packet-analysis scripts.
"""

from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path
from typing import Any, Dict, List


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Flatten snapshot capture JSON files into one flowlet feature JSON."
    )
    parser.add_argument(
        "snapshot_dir",
        help="Path to snapshot directory containing captures/ and manifest.json",
    )
    parser.add_argument(
        "--provider",
        default="gemini",
        choices=["gemini", "chatgpt", "claude"],
        help="LLM provider label for source_file tagging (default: gemini)",
    )
    parser.add_argument(
        "--output-name",
        default="flowlet_features_incoming_ready.json",
        help="Output file name created inside snapshot_dir",
    )
    return parser.parse_args()


def flatten_snapshot(snapshot_dir: Path, provider: str) -> List[Dict[str, Any]]:
    captures_dir = snapshot_dir / "captures"
    if not captures_dir.exists() or not captures_dir.is_dir():
        raise FileNotFoundError(f"captures directory not found: {captures_dir}")

    capture_files = sorted(glob.glob(str(captures_dir / "*.json")))
    if not capture_files:
        raise FileNotFoundError(f"no capture JSON files found in {captures_dir}")

    rows: List[Dict[str, Any]] = []
    for capture_path in capture_files:
        cap_name = Path(capture_path).name
        with open(capture_path, "r", encoding="utf-8") as f:
            doc = json.load(f)

        flowlets = doc.get("flowlets", [])
        if not isinstance(flowlets, list):
            continue

        for fl in flowlets:
            if not isinstance(fl, dict):
                continue

            traffic_class = fl.get("traffic_class")
            if traffic_class == "llm":
                fl["source_file"] = f"{provider}_snapshot/{cap_name}"
            else:
                fl["source_file"] = f"snapshot_non_llm/{cap_name}"
            rows.append(fl)

    return rows


def main() -> None:
    args = parse_args()

    snapshot_dir = Path(args.snapshot_dir).expanduser().resolve()
    output_path = snapshot_dir / args.output_name

    rows = flatten_snapshot(snapshot_dir=snapshot_dir, provider=args.provider)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)

    print(f"Wrote {len(rows)} flowlets to {output_path}")


if __name__ == "__main__":
    main()
