#!/usr/bin/env python3
"""
parse_flowlets_tls_simple.py

TLS-record–based version of parse_flowlets_simple.py.
Uses TLS application-data records instead of packets.

Input: directory of *.tsv files (TLS record streams)
Output: combined flowlet feature JSON

Usage:
  python3 parse_flowlets_tls_simple.py \
    --input tls_records/chatgpt_ipv4 \
    --output flowlets_tls.json
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any, Optional

from parse_tls_records import parse_tls_records_with_headers


# -----------------------------
# Flow grouping (TLS streams)
# -----------------------------
def group_records_into_flows(records: List[Dict[str, Any]]):
    flows = defaultdict(list)
    for r in records:
        flows[r["stream"]].append(r)
    return flows


# -----------------------------
# Flowlet splitting (TLS gaps)
# -----------------------------
def split_flowlets(records: List[Dict[str, Any]], threshold: float):
    records = sorted(records, key=lambda r: r["ts"])
    if not records:
        return []

    flowlets = []
    cur = {
        "start_ts": records[0]["ts"],
        "end_ts": records[0]["ts"],
        "records": [records[0]],
        "bytes": records[0]["length"],
    }

    last_ts = records[0]["ts"]

    for r in records[1:]:
        gap = r["ts"] - last_ts
        if gap > threshold:
            flowlets.append(cur)
            cur = {
                "start_ts": r["ts"],
                "end_ts": r["ts"],
                "records": [r],
                "bytes": r["length"],
            }
        else:
            cur["end_ts"] = r["ts"]
            cur["records"].append(r)
            cur["bytes"] += r["length"]
        last_ts = r["ts"]

    flowlets.append(cur)
    return flowlets


# -----------------------------
# Feature computation
# -----------------------------
def compute_record_statistics(records: List[Dict[str, Any]]):
    times = [r["ts"] for r in records]
    sizes = [r["length"] for r in records]

    ipg = [times[i] - times[i - 1] for i in range(1, len(times))]

    return {
        "inter_packet_times": ipg,
        "inter_packet_time_mean": statistics.mean(ipg) if ipg else 0.0,
        "inter_packet_time_std": statistics.stdev(ipg) if len(ipg) > 1 else 0.0,
        "packet_sizes": sizes,
        "packet_size_mean": statistics.mean(sizes) if sizes else 0.0,
        "packet_size_std": statistics.stdev(sizes) if len(sizes) > 1 else 0.0,
    }


# -----------------------------
# Direction + LLM labeling
# -----------------------------
def determine_direction(src_ip, dst_ip, llm_ip_map):
    if dst_ip in llm_ip_map:
        return True, 1   # user → LLM
    if src_ip in llm_ip_map:
        return False, -1 # LLM → user
    return None, 0


# -----------------------------
# Flowlet feature extraction
# -----------------------------
def extract_flowlet_features(
    flows,
    threshold: float,
    source_file: str,
    llm_ip_map: Dict[str, str],
):
    features = []

    for stream_id, records in flows.items():
        flowlets = split_flowlets(records, threshold)

        for idx, fl in enumerate(flowlets, start=1):
            recs = fl["records"]
            stats = compute_record_statistics(recs)

            src_ip = recs[0]["src_ip"]
            dst_ip = recs[0]["dst_ip"]

            llm_name = llm_ip_map.get(src_ip) or llm_ip_map.get(dst_ip)
            outgoing, direction_encoded = determine_direction(
                src_ip, dst_ip, llm_ip_map
            )

            feature = {
                "flow_key": {
                    "tcp_stream": stream_id,
                    "src_ip": src_ip,
                    "src_port": recs[0]["src_port"],
                    "dst_ip": dst_ip,
                    "dst_port": recs[0]["dst_port"],
                    "protocol": "TLS",
                },
                "flowlet_id": idx,
                "traffic_class": "llm" if llm_name else "non_llm",
                "llm_name": llm_name,
                "source_file": source_file,
                # Direction
                "outgoing": outgoing,
                "direction_encoded": direction_encoded,
                # Flowlet timing
                "start_ts": fl["start_ts"],
                "end_ts": fl["end_ts"],
                "duration": fl["end_ts"] - fl["start_ts"],
                # Size
                "packet_count": len(recs),        # TLS records
                "total_bytes": fl["bytes"],       # sum of TLS record sizes
                # Statistics (mirrors packet version)
                **stats,
            }

            features.append(feature)

    return features


# -----------------------------
# Directory pipeline
# -----------------------------
def parse_directory(
    input_dir: Path,
    pattern: str,
    threshold: float,
):
    global_llm_ip_map: Dict[str, str] = {}
    all_features = []

    files = sorted(input_dir.glob(pattern))
    if not files:
        raise FileNotFoundError("No TLS TSV files found")

    for f in files:
        print(f"Processing {f}")

        records, file_llm_map = parse_tls_records_with_headers(f)

        # Merge file-local ground truth into global map
        global_llm_ip_map.update(file_llm_map)

        flows = group_records_into_flows(records)

        feats = extract_flowlet_features(
            flows,
            threshold,
            source_file=str(f),
            llm_ip_map=global_llm_ip_map,
        )
        all_features.extend(feats)

    return all_features



# -----------------------------
# CLI
# -----------------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--pattern", default="*.tsv")
    p.add_argument("--threshold", type=float, default=0.1)
    p.add_argument("--output", required=True)
    args = p.parse_args()

    features = parse_directory(
        Path(args.input),
        args.pattern,
        args.threshold,
    )

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(features, f, indent=2)

    llm_count = sum(1 for f in features if f["traffic_class"] == "llm")
    print(f"Saved {len(features)} flowlets ({llm_count} LLM) → {args.output}")


if __name__ == "__main__":
    main()
