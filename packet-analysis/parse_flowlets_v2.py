#!/usr/bin/env python3
"""parse_flowlets_simple.py

Minimal parser that walks a directory of capture text files, extracts flowlets,
and writes a single combined JSON of flowlet features. LLM sources are declared
at the top of each capture in lines like:

    LLM_IP <LLM_NAME> <LLM_SOURCE_IP>

All flowlets involving those IPs are marked as LLM traffic.

Usage:
    python3 parse_flowlets_simple.py --input captures/chatgpt_ipv4 --output flowlets.json
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Regexes reused from the full parser
TS_LINE_RE = re.compile(r"^(?P<ts>\d{2}:\d{2}:\d{2}\.\d+)\s+(?P<family>IP6|IP)\b", re.IGNORECASE)
PROTO_HINT_RE = re.compile(r"(?:proto|next-header)\s+(?P<proto>[A-Za-z0-9_]+)", re.IGNORECASE)
LENGTH_RE = re.compile(r"length\s+(?P<len>\d+)", re.IGNORECASE)
LLM_HEADER_RE = re.compile(r"^LLM_IP\s+(?P<llm>[^\s]+)\s+(?P<ip>[^\s]+)$", re.IGNORECASE)


# -----------------------------
# Packet and flowlet extraction
# -----------------------------
def extract_proto(header_line: str) -> str:
    match = PROTO_HINT_RE.search(header_line)
    if match:
        return match.group("proto").upper()
    return "UNKNOWN"


def split_host_port(token: str) -> Tuple[Optional[str], Optional[int]]:
    token = token.strip()
    if not token:
        return None, None
    if "." in token:
        host_candidate, possible_port = token.rsplit(".", 1)
        if possible_port.isdigit():
            return host_candidate, int(possible_port)
    return token, None


def parse_address_line(
    line: str,
) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[int], str]:
    if ">" not in line:
        return None, None, None, None, line
    left, right = line.split(">", 1)
    src_ip, src_port = split_host_port(left.strip())
    right = right.strip()
    if ":" in right:
        dst_part, remainder = right.split(":", 1)
    else:
        dst_part, remainder = right, ""
    dst_ip, dst_port = split_host_port(dst_part.strip())
    return src_ip, src_port, dst_ip, dst_port, remainder


def ts_to_seconds(ts_str: str) -> float:
    """Convert hh:mm:ss.sss to seconds since midnight as float."""
    h, m, s = ts_str.split(":")
    return int(h) * 3600 + int(m) * 60 + float(s)


def parse_capture_text(
    path: Path,
    start_idx: int = 0,
    preloaded_lines: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Parse packet lines from a capture into packet dicts."""
    packets = []
    if preloaded_lines is None:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            lines = [l.rstrip("\n") for l in f]
    else:
        lines = preloaded_lines

    i = start_idx
    while i < len(lines):
        line = lines[i]
        m = TS_LINE_RE.match(line)
        if m:
            ts_str = m.group("ts")
            proto = extract_proto(line)
            ts = ts_to_seconds(ts_str)
            addr_line = lines[i + 1] if i + 1 < len(lines) else None

            src = dst = sport = dport = None
            length = None
            if addr_line:
                src, sport, dst, dport, remainder = parse_address_line(addr_line)
                length_match = LENGTH_RE.search(addr_line)
                if length_match:
                    length = int(length_match.group("len"))

            if length is None:
                ml2 = LENGTH_RE.search(line)
                if ml2:
                    length = int(ml2.group("len"))

            pkt = {
                "ts": ts,
                "proto": proto,
                "src_ip": src,
                "src_port": int(sport) if sport else None,
                "dst_ip": dst,
                "dst_port": int(dport) if dport else None,
                "length": length,
                "raw": (line, addr_line) if addr_line is not None else (line, None),
            }
            packets.append(pkt)
            i += 2 if addr_line is not None else 1
        else:
            i += 1

    return packets


def canonical_flow_key(pkt: Dict[str, Any], bidirectional: bool = False) -> Tuple:
    """Return a flow key tuple (src, sport, dst, dport, proto).

    If bidirectional is True the tuple is ordered so both directions map to same key.
    """
    src = pkt["src_ip"] or ""
    dst = pkt["dst_ip"] or ""
    sport = pkt["src_port"] or 0
    dport = pkt["dst_port"] or 0
    proto = (pkt["proto"] or "").upper()
    if not bidirectional:
        return (src, sport, dst, dport, proto)

    a = f"{src}:{sport}"
    b = f"{dst}:{dport}"
    if a <= b:
        return (src, sport, dst, dport, proto)
    return (dst, dport, src, sport, proto)


def group_packets_into_flows(
    packets: List[Dict[str, Any]], bidirectional: bool = False
) -> Dict[Tuple, List[Dict[str, Any]]]:
    flows = defaultdict(list)
    for pkt in packets:
        key = canonical_flow_key(pkt, bidirectional=bidirectional)
        flows[key].append(pkt)
    return flows


def split_flowlets(
    flow_pkts: List[Dict[str, Any]], threshold: float = 0.1
) -> List[Dict[str, Any]]:
    """Split packets of a flow into flowlets using an inter-packet gap threshold."""
    if not flow_pkts:
        return []

    flowlets = []
    current = {
        "start_ts": flow_pkts[0]["ts"],
        "end_ts": flow_pkts[0]["ts"],
        "packets": 1,
        "bytes": flow_pkts[0].get("length") or 0,
        "pkts": [flow_pkts[0]],
    }

    last_ts = flow_pkts[0]["ts"]
    for pkt in flow_pkts[1:]:
        delta = pkt["ts"] - last_ts
        if delta > threshold:
            flowlets.append(current)
            current = {
                "start_ts": pkt["ts"],
                "end_ts": pkt["ts"],
                "packets": 1,
                "bytes": pkt.get("length") or 0,
                "pkts": [pkt],
            }
        else:
            current["end_ts"] = pkt["ts"]
            current["packets"] += 1
            current["bytes"] += pkt.get("length") or 0
            current["pkts"].append(pkt)
        last_ts = pkt["ts"]

    flowlets.append(current)
    return flowlets


def compute_packet_statistics(pkts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute basic statistics for a list of packets."""
    if not pkts:
        return {
            "inter_packet_times": [],
            "inter_packet_time_mean": 0.0,
            "inter_packet_time_std": 0.0,
            "packet_sizes": [],
            "packet_size_mean": 0.0,
            "packet_size_std": 0.0,
        }

    sorted_pkts = sorted(pkts, key=lambda p: p["ts"])
    inter_packet_times = [
        sorted_pkts[i]["ts"] - sorted_pkts[i - 1]["ts"] for i in range(1, len(sorted_pkts))
    ]
    packet_sizes = [p.get("length", 0) or 0 for p in sorted_pkts]

    import statistics

    ipt_mean = statistics.mean(inter_packet_times) if inter_packet_times else 0.0
    ipt_std = statistics.stdev(inter_packet_times) if len(inter_packet_times) > 1 else 0.0
    ps_mean = statistics.mean(packet_sizes) if packet_sizes else 0.0
    ps_std = statistics.stdev(packet_sizes) if len(packet_sizes) > 1 else 0.0

    return {
        "inter_packet_times": inter_packet_times,
        "inter_packet_time_mean": ipt_mean,
        "inter_packet_time_std": ipt_std,
        "packet_sizes": packet_sizes,
        "packet_size_mean": ps_mean,
        "packet_size_std": ps_std,
    }


# -----------------------------
# LLM tagging helpers
# -----------------------------
def parse_llm_header(lines: List[str]) -> Tuple[Dict[str, str], int]:
    """Parse leading LLM_IP lines and return (llm_ip_map, start_idx for packets)."""
    llm_map: Dict[str, str] = {}
    idx = 0
    while idx < len(lines):
        line = lines[idx].strip()
        if not line:
            idx += 1
            continue
        m = LLM_HEADER_RE.match(line)
        if not m:
            break
        llm_name = m.group("llm").strip()
        llm_ip = m.group("ip").strip()
        llm_map[llm_ip] = llm_name
        idx += 1
    return llm_map, idx


# -----------------------------
# Flowlet feature extraction
# -----------------------------
def extract_flowlet_features(
    flows: Dict[Tuple, List[Dict[str, Any]]],
    threshold: float,
    source_file: str,
    llm_ip_map: Dict[str, str],
) -> List[Dict[str, Any]]:
    """Build feature dicts for all flowlets in the given flows."""
    flowlet_features = []

    for flow_key, pkts in flows.items():
        src_ip, src_port, dst_ip, dst_port, proto = flow_key
        pkts_sorted = sorted(pkts, key=lambda x: x["ts"])
        flowlets = split_flowlets(pkts_sorted, threshold=threshold)

        for idx, flowlet in enumerate(flowlets, start=1):
            stats = compute_packet_statistics(flowlet["pkts"])
            llm_name = None
            for ip in (src_ip, dst_ip):
                if ip and ip in llm_ip_map:
                    llm_name = llm_ip_map[ip]
                    break

            feature = {
                "flow_key": {
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": proto,
                },
                "flowlet_id": idx,
                "traffic_class": "llm" if llm_name else "non_llm",
                "llm_name": llm_name,
                "source_file": source_file,
                "start_ts": flowlet["start_ts"],
                "end_ts": flowlet["end_ts"],
                "duration": flowlet["end_ts"] - flowlet["start_ts"],
                "packet_count": flowlet["packets"],
                "total_bytes": flowlet["bytes"],
                "inter_packet_time_mean": stats["inter_packet_time_mean"],
                "inter_packet_time_std": stats["inter_packet_time_std"],
                "packet_size_mean": stats["packet_size_mean"],
                "packet_size_std": stats["packet_size_std"],
                "inter_packet_times": stats["inter_packet_times"],
                "packet_sizes": stats["packet_sizes"],
            }
            flowlet_features.append(feature)

    return flowlet_features


# -----------------------------
# Main pipeline
# -----------------------------
def process_capture_file(
    capture_path: Path,
    threshold: float,
    bidirectional: bool,
    llm_ip_map: Dict[str, str],
) -> List[Dict[str, Any]]:
    """Parse one capture file and return its flowlet feature dicts."""
    with capture_path.open("r", encoding="utf-8", errors="replace") as f:
        lines = [l.rstrip("\n") for l in f]

    header_llm_map, start_idx = parse_llm_header(lines)
    for ip, llm_name in header_llm_map.items():
        llm_ip_map[ip] = llm_name

    packets = parse_capture_text(
        capture_path, start_idx=start_idx, preloaded_lines=lines
    )

    flows = group_packets_into_flows(packets, bidirectional=bidirectional)
    features = extract_flowlet_features(
        flows,
        threshold=threshold,
        source_file=str(capture_path),
        llm_ip_map=llm_ip_map,
    )
    return features


def parse_directory(
    input_dir: Path,
    pattern: str,
    threshold: float,
    bidirectional: bool,
) -> List[Dict[str, Any]]:
    """Process all capture files in a directory and return combined flowlets."""
    llm_ip_map: Dict[str, str] = {}
    all_features: List[Dict[str, Any]] = []

    files = sorted(input_dir.glob(pattern))
    if not files:
        raise FileNotFoundError(f"No capture files matching pattern '{pattern}' in {input_dir}")

    for capture_file in files:
        print(f"Processing {capture_file} ...")
        features = process_capture_file(
            capture_file,
            threshold=threshold,
            bidirectional=bidirectional,
            llm_ip_map=llm_ip_map,
        )
        all_features.extend(features)

    return all_features


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Parse a directory of capture text files into flowlets, tagging LLM IPs."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Directory containing capture text files.",
    )
    parser.add_argument(
        "--pattern",
        default="capture*.txt",
        help="Glob pattern for capture files (default: capture*.txt).",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.1,
        help="Flowlet inter-packet gap threshold in seconds (default: 0.1).",
    )
    parser.add_argument(
        "--bidirectional",
        action="store_true",
        help="Treat flows as bidirectional when grouping.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="flowlets_combined.json",
        help="Path to write combined flowlet feature JSON.",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    input_dir = Path(args.input)
    if not input_dir.is_dir():
        raise NotADirectoryError(f"Input path {input_dir} is not a directory")

    all_features = parse_directory(
        input_dir=input_dir,
        pattern=args.pattern,
        threshold=args.threshold,
        bidirectional=args.bidirectional,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(all_features, f, indent=2)

    llm_flowlets = sum(1 for f in all_features if f["traffic_class"] == "llm")
    print(
        f"Saved {len(all_features)} flowlets ({llm_flowlets} tagged as LLM) to {output_path}"
    )


if __name__ == "__main__":
    main()

