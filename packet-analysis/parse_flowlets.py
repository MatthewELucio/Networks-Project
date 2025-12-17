#!/usr/bin/env python3
"""parse_flowlets.py

Read a tcpdump-style text capture (the project's `capture_*.txt`) and
produce flows (5-tuples) and flowlets split by an inter-packet-gap threshold.

Usage: python3 parse_flowlets.py <capture.txt | captures_dir> --threshold 0.1 --bidirectional --output out.json
"""
import argparse
import json
import re
import ipaddress
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Any

# Regexes
TS_LINE_RE = re.compile(
    r"^(?P<ts>\d{2}:\d{2}:\d{2}\.\d+)\s+(?P<family>IP6|IP)\b", re.IGNORECASE
)
PROTO_HINT_RE = re.compile(
    r"(?:proto|next-header)\s+(?P<proto>[A-Za-z0-9_]+)", re.IGNORECASE
)
LENGTH_RE = re.compile(r"length\s+(?P<len>\d+)", re.IGNORECASE)


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


def resolve_input_paths(target: str, glob_pattern: str) -> List[Path]:
    path = Path(target)
    if path.is_file():
        return [path]
    if path.is_dir():
        candidates = sorted(path.glob(glob_pattern))
        if not candidates:
            raise FileNotFoundError(
                f"No files matched pattern {glob_pattern!r} in {path}"
            )
        return candidates
    raise FileNotFoundError(f"Input path {target} does not exist")


def ts_to_seconds(ts_str: str) -> float:
    """Convert hh:mm:ss.sss to seconds since midnight as float."""
    h, m, s = ts_str.split(":")
    return int(h) * 3600 + int(m) * 60 + float(s)


def parse_capture_text(path: Path) -> List[Dict[str, Any]]:
    """Parse the capture text and return list of packet dicts.

    Each packet dict contains: ts (float seconds), proto, src_ip, src_port (int|None),
    dst_ip, dst_port (int|None), length (int|None), raw_lines (2-line tuple).
    """
    packets = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        lines = [l.rstrip("\n") for l in f]

    i = 0
    while i < len(lines):
        line = lines[i]
        m = TS_LINE_RE.match(line)
        if m:
            ts_str = m.group("ts")
            proto = extract_proto(line)
            ts = ts_to_seconds(ts_str)
            # look ahead for address line
            addr_line = None
            if i + 1 < len(lines):
                addr_line = lines[i + 1]

            src = dst = sport = dport = None
            length = None
            if addr_line:
                src, sport, dst, dport, remainder = parse_address_line(addr_line)
                # try to get length from the addr line (including remainder portion)
                length_match = LENGTH_RE.search(addr_line)
                if length_match:
                    length = int(length_match.group("len"))

            # also try length from the TS line if not found
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
            # advance by 2 if we consumed an addr line, else by 1
            if addr_line is not None:
                i += 2
            else:
                i += 1
        else:
            i += 1

    return packets


def load_packets(
    input_path: str, glob_pattern: str
) -> Tuple[List[Dict[str, Any]], List[Path]]:
    paths = resolve_input_paths(input_path, glob_pattern)
    packets: List[Dict[str, Any]] = []
    for path in paths:
        parsed = parse_capture_text(path)
        for pkt in parsed:
            pkt["source_file"] = str(path)
        packets.extend(parsed)
    return packets, paths


def canonical_flow_key(pkt: Dict[str, Any], bidirectional: bool = False) -> Tuple:
    """Return a flow key tuple (src, sport, dst, dport, proto).

    If bidirectional is True the tuple is ordered so both directions map to same key.
    """
    src = pkt["src_ip"] or ""
    dst = pkt["dst_ip"] or ""
    sport = pkt["src_port"] or 0
    dport = pkt["dst_port"] or 0
    proto = (pkt["proto"] or "").upper()
    key = (src, sport, dst, dport, proto)
    if not bidirectional:
        return key

    # order by (ip,port) string comparison to get canonical direction
    a = f"{src}:{sport}"
    b = f"{dst}:{dport}"
    if a <= b:
        return (src, sport, dst, dport, proto)
    else:
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
    """Split a list of packets (one flow) into flowlets by inter-packet gap threshold (seconds).

    Returns list of flowlets with keys: start_ts, end_ts, packets (count), bytes, pkts (list of pkts)
    """
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


def build_summary(
    flows: Dict[Tuple, List[Dict[str, Any]]], threshold: float, bidirectional: bool
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "flows_count": len(flows),
        "threshold": threshold,
        "bidirectional": bidirectional,
        "flows": [],
    }

    for key, pkts in flows.items():
        # packets should already be in chronological order
        pkts_sorted = sorted(pkts, key=lambda x: x["ts"])
        total_bytes = sum(p.get("length") or 0 for p in pkts_sorted)
        flow_info: Dict[str, Any] = {
            "flow_key": key,
            "packets": len(pkts_sorted),
            "bytes": total_bytes,
            "start_ts": pkts_sorted[0]["ts"] if pkts_sorted else None,
            "end_ts": pkts_sorted[-1]["ts"] if pkts_sorted else None,
            "flowlets": [],
        }
        flowlets = split_flowlets(pkts_sorted, threshold=threshold)
        # summarize flowlets
        for idx, f in enumerate(flowlets, start=1):
            flowlet_summary = {
                "id": idx,
                "start_ts": f["start_ts"],
                "end_ts": f["end_ts"],
                "packets": f["packets"],
                "bytes": f["bytes"],
                "query_id": None,
                "query_role": None,
            }
            flow_info["flowlets"].append(flowlet_summary)

        out["flows"].append(flow_info)

    return out


def is_private_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def infer_flow_direction(
    flow_key: Tuple,
    client_ip: Optional[str] = None,
    server_ip: Optional[str] = None,
) -> str:
    src, sport, dst, dport, _ = flow_key

    if client_ip:
        if src == client_ip:
            return "client_to_server"
        if dst == client_ip:
            return "server_to_client"
    if server_ip:
        if src == server_ip:
            return "server_to_client"
        if dst == server_ip:
            return "client_to_server"

    if is_private_ip(src) and not is_private_ip(dst):
        return "client_to_server"
    if is_private_ip(dst) and not is_private_ip(src):
        return "server_to_client"

    if dport == 443 and sport != 443:
        return "client_to_server"
    if sport == 443 and dport != 443:
        return "server_to_client"

    return "unknown"


def annotate_queries(
    summary: Dict[str, Any],
    client_ip: Optional[str] = None,
    server_ip: Optional[str] = None,
) -> None:
    flows = summary.get("flows", [])
    timeline = []
    for flow in flows:
        direction = infer_flow_direction(
            flow["flow_key"], client_ip=client_ip, server_ip=server_ip
        )
        flow["direction"] = direction
        for flowlet in flow["flowlets"]:
            flowlet["direction"] = direction
            if direction in {"client_to_server", "server_to_client"}:
                timeline.append(
                    {
                        "direction": direction,
                        "start": flowlet["start_ts"],
                        "end": flowlet["end_ts"],
                        "bytes": flowlet["bytes"],
                        "flow_key": flow["flow_key"],
                        "flowlet_id": flowlet["id"],
                        "flowlet": flowlet,
                    }
                )

    timeline.sort(key=lambda item: item["start"])
    client_events = [ev for ev in timeline if ev["direction"] == "client_to_server"]
    server_events = [ev for ev in timeline if ev["direction"] == "server_to_client"]

    queries = []
    for idx, upload_event in enumerate(client_events, start=1):
        next_client_start = None
        if idx < len(client_events):
            next_client_start = client_events[idx]["start"]

        resp_candidates = [
            ev
            for ev in server_events
            if ev["start"] >= upload_event["end"]
            and (next_client_start is None or ev["start"] < next_client_start)
        ]

        response_start = resp_candidates[0]["start"] if resp_candidates else None
        response_end = max((ev["end"] for ev in resp_candidates), default=None)
        response_bytes = sum(ev["bytes"] for ev in resp_candidates)

        upload_event["flowlet"]["query_id"] = idx
        upload_event["flowlet"]["query_role"] = "upload"

        response_flowlets = []
        for resp_ev in resp_candidates:
            resp_ev["flowlet"]["query_id"] = idx
            resp_ev["flowlet"]["query_role"] = "response"
            response_flowlets.append(
                {
                    "flow_key": resp_ev["flow_key"],
                    "flowlet_id": resp_ev["flowlet_id"],
                    "start_ts": resp_ev["start"],
                    "end_ts": resp_ev["end"],
                    "bytes": resp_ev["bytes"],
                }
            )

        queries.append(
            {
                "id": idx,
                "upload_flow": upload_event["flow_key"],
                "upload_flowlet_id": upload_event["flowlet_id"],
                "upload_start_ts": upload_event["start"],
                "upload_end_ts": upload_event["end"],
                "upload_bytes": upload_event["bytes"],
                "response_start_ts": response_start,
                "response_end_ts": response_end,
                "response_bytes": response_bytes,
                "response_flowlets": response_flowlets,
                "confidence": "high" if resp_candidates else "low",
            }
        )

    summary["queries"] = queries


def export_to_traffic_json(
    summary: Dict[str, Any], base_timestamp: str = "2025-12-01T21:00:00.000Z"
) -> List[Dict[str, Any]]:
    """Convert parsed summary to the traffic event format used by the front-end.

    Args:
        summary: The summary dict from build_summary + annotate_queries
        base_timestamp: ISO timestamp to use as the base (flowlet timestamps are relative seconds)

    Returns:
        List of traffic event dicts matching the mock_traffic.json format
    """
    from datetime import datetime, timedelta

    # Parse base timestamp
    base_dt = datetime.fromisoformat(base_timestamp.replace("Z", "+00:00"))

    events = []
    event_id = 1

    for flow in summary.get("flows", []):
        flow_key = flow["flow_key"]
        src_ip, src_port, dst_ip, dst_port, proto = flow_key

        for flowlet in flow["flowlets"]:
            # Calculate timestamp from base + flowlet start
            event_dt = base_dt + timedelta(seconds=flowlet["start_ts"])
            timestamp = event_dt.isoformat().replace("+00:00", "Z")

            # Build base event
            event = {
                "id": f"evt_{event_id}",
                "timestamp": timestamp,
                "userId": "unknown",  # Could be inferred from IP if mapping available
                "srcIp": src_ip or "unknown",
                "dstIp": dst_ip or "unknown",
                "bytes": flowlet["bytes"],
                "protocol": proto or "UNKNOWN",
            }

            # Add LLM-related fields if this flowlet is part of a query
            if flowlet.get("query_id") is not None:
                event["llmUsage"] = True
                event["llmProvider"] = "unknown"  # Could be inferred from dst_ip
                event["llmModel"] = "unknown"

                # Find the query to get confidence
                queries = summary.get("queries", [])
                matching_query = next(
                    (q for q in queries if q["id"] == flowlet["query_id"]), None
                )
                if matching_query:
                    confidence_map = {"high": 0.9, "medium": 0.7, "low": 0.5}
                    event["llmConfidence"] = confidence_map.get(
                        matching_query.get("confidence", "low"), 0.5
                    )
            else:
                event["llmUsage"] = False

            events.append(event)
            event_id += 1

    return events


def compute_packet_statistics(pkts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute statistical features from packet-level data.
    
    Returns dict with:
    - inter_packet_times: list of time gaps between consecutive packets
    - inter_packet_time_mean: mean of inter-packet times
    - inter_packet_time_std: std dev of inter-packet times
    - packet_sizes: list of packet sizes (bytes)
    - packet_size_mean: mean packet size
    - packet_size_std: std dev of packet size
    """
    if not pkts:
        return {
            "inter_packet_times": [],
            "inter_packet_time_mean": 0.0,
            "inter_packet_time_std": 0.0,
            "packet_sizes": [],
            "packet_size_mean": 0.0,
            "packet_size_std": 0.0,
        }
    
    # Sort by timestamp
    sorted_pkts = sorted(pkts, key=lambda p: p["ts"])
    
    # Compute inter-packet times
    inter_packet_times = []
    for i in range(1, len(sorted_pkts)):
        gap = sorted_pkts[i]["ts"] - sorted_pkts[i-1]["ts"]
        inter_packet_times.append(gap)
    
    # Compute packet sizes
    packet_sizes = [p.get("length", 0) or 0 for p in sorted_pkts]
    
    # Calculate statistics
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


def extract_flowlet_features(
    flows: Dict[Tuple, List[Dict[str, Any]]], 
    threshold: float,
    traffic_class: str,
    source_file: str
) -> List[Dict[str, Any]]:
    """Extract detailed flowlet features including packet-level statistics.
    
    Returns list of flowlet feature dicts suitable for ML training.
    """
    flowlet_features = []
    
    for flow_key, pkts in flows.items():
        src_ip, src_port, dst_ip, dst_port, proto = flow_key
        
        # Sort packets by timestamp
        pkts_sorted = sorted(pkts, key=lambda x: x["ts"])
        
        # Split into flowlets
        flowlets = split_flowlets(pkts_sorted, threshold=threshold)
        
        for idx, flowlet in enumerate(flowlets, start=1):
            # Compute packet-level statistics
            stats = compute_packet_statistics(flowlet["pkts"])
            
            # Build feature dict
            feature = {
                "flow_key": {
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": proto,
                },
                "flowlet_id": idx,
                "traffic_class": traffic_class,
                "source_file": source_file,
                # Flowlet-level features
                "start_ts": flowlet["start_ts"],
                "end_ts": flowlet["end_ts"],
                "duration": flowlet["end_ts"] - flowlet["start_ts"],
                "packet_count": flowlet["packets"],
                "total_bytes": flowlet["bytes"],
                # Packet-level statistics
                "inter_packet_time_mean": stats["inter_packet_time_mean"],
                "inter_packet_time_std": stats["inter_packet_time_std"],
                "packet_size_mean": stats["packet_size_mean"],
                "packet_size_std": stats["packet_size_std"],
                # Raw sequences for potential Markov modeling
                "inter_packet_times": stats["inter_packet_times"],
                "packet_sizes": stats["packet_sizes"],
            }
            
            flowlet_features.append(feature)
    
    return flowlet_features


def parse_captures_to_features(
    captures_root: str,
    file_pattern: str = "capture*.txt",
    threshold: float = 0.1,
    bidirectional: bool = False,
    output_file: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Parse all captures and extract flowlet features for ML training.
    
    Args:
        captures_root: Root directory containing capture subdirectories
        file_pattern: Glob pattern for capture files
        threshold: Flowlet gap threshold in seconds
        bidirectional: Whether to treat flows as bidirectional
        output_file: Optional path to save JSON output
        
    Returns:
        List of flowlet feature dicts
    """
    from pathlib import Path
    
    all_features = []
    captures_path = Path(captures_root)
    
    # Define traffic classes based on directory structure
    traffic_class_map = {
        "chatgpt_ipv4": "llm",
        "chatgpt_ipv6": "llm",
        "claude_ipv4": "llm",
        "claude_ipv6": "llm",
        "gemini_ipv4": "llm",
        "gemini_ipv6": "llm",
        "all_v6": "non_llm",
        "all_v4": "non_llm",
    }
    
    # Process each subdirectory
    for subdir in captures_path.iterdir():
        if not subdir.is_dir():
            continue
            
        traffic_class = traffic_class_map.get(subdir.name, "unknown")
        if traffic_class == "unknown":
            continue
        
        # Find all capture files in this subdirectory
        capture_files = sorted(subdir.glob(file_pattern))
        
        for capture_file in capture_files:
            print(f"Processing {capture_file}...")
            
            # Parse packets from this capture
            packets = parse_capture_text(capture_file)
            for pkt in packets:
                pkt["source_file"] = str(capture_file)
            
            # Group into flows
            flows = group_packets_into_flows(packets, bidirectional=bidirectional)
            
            # Extract features
            features = extract_flowlet_features(
                flows, 
                threshold=threshold,
                traffic_class=traffic_class,
                source_file=str(capture_file)
            )
            
            all_features.extend(features)
    
    # Save to file if requested
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(all_features, f, indent=2)
        print(f"Saved {len(all_features)} flowlet features to {output_file}")
    
    return all_features


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Parse tcpdump-style text into flows, flowlets, and estimated LLM queries"
    )
    p.add_argument(
        "input", nargs="?", help="capture text file or directory containing capture_*.txt files"
    )
    p.add_argument(
        "--threshold",
        "-t",
        type=float,
        default=0.1,
        help="flowlet gap threshold in seconds (default: 0.1s)",
    )
    p.add_argument(
        "--bidirectional",
        "-b",
        action="store_true",
        help="treat flows as bidirectional (fold directions)",
    )
    p.add_argument(
        "--client-ip",
        help="hint for which IP is the ChatGPT client (helps direction inference)",
    )
    p.add_argument(
        "--server-ip", help="hint for which IP is the ChatGPT backend (LLM) server"
    )
    p.add_argument(
        "--pattern",
        default="capture*.txt",
        help="glob pattern when input is a directory (default: capture*.txt)",
    )
    p.add_argument("--output", "-o", help="write JSON summary to this file")
    p.add_argument(
        "--traffic-json", help="write traffic events in front-end format to this file"
    )
    p.add_argument(
        "--base-timestamp",
        default="2025-12-01T21:00:00.000Z",
        help="base ISO timestamp for traffic-json output",
    )
    p.add_argument(
        "--sample",
        action="store_true",
        help="print a small human-readable sample summary",
    )
    p.add_argument(
        "--extract-features",
        action="store_true",
        help="extract flowlet features for ML training (use with --captures-root)",
    )
    p.add_argument(
        "--captures-root",
        default="captures",
        help="root directory containing capture subdirectories (for --extract-features)",
    )
    p.add_argument(
        "--features-output",
        help="output file for extracted features JSON (for --extract-features)",
    )
    args = p.parse_args(argv)

    # Handle feature extraction mode
    if args.extract_features:
        if not args.features_output:
            print("Error: --features-output is required when using --extract-features")
            return
        features = parse_captures_to_features(
            captures_root=args.captures_root,
            file_pattern=args.pattern,
            threshold=args.threshold,
            bidirectional=args.bidirectional,
            output_file=args.features_output,
        )
        print(f"Extracted {len(features)} flowlet features")
        return

    if not args.input:
        print("Error: input argument is required when not using --extract-features")
        return

    packets, input_files = load_packets(args.input, args.pattern)
    flows = group_packets_into_flows(packets, bidirectional=args.bidirectional)
    summary = build_summary(
        flows, threshold=args.threshold, bidirectional=args.bidirectional
    )
    annotate_queries(summary, client_ip=args.client_ip, server_ip=args.server_ip)
    summary["source_files"] = [str(p) for p in input_files]

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
        print(f"Wrote JSON summary to {args.output}")

    if args.traffic_json:
        traffic_events = export_to_traffic_json(
            summary, base_timestamp=args.base_timestamp
        )
        with open(args.traffic_json, "w", encoding="utf-8") as fh:
            json.dump(traffic_events, fh, indent=2)
        print(f"Wrote {len(traffic_events)} traffic events to {args.traffic_json}")

    if args.sample or not args.output:
        # print brief summary
        print(
            f"Files: {len(input_files)}, packets={len(packets)}, flows={summary['flows_count']}, "
            f"threshold={summary['threshold']}s, bidir={summary['bidirectional']}"
        )
        # print top 10 flows by bytes
        flows_sorted = sorted(summary["flows"], key=lambda x: x["bytes"], reverse=True)
        for f in flows_sorted[:10]:
            key = f["flow_key"]
            print(
                f"Flow {key}: pkts={f['packets']}, bytes={f['bytes']}, flowlets={len(f['flowlets'])}, start={f['start_ts']}, end={f['end_ts']}"
            )

        queries = summary.get("queries", [])
        print(f"Detected {len(queries)} probable LLM queries")
        for q in queries[:10]:
            upload_range = (
                f"{q['upload_start_ts']:.6f}-{q['upload_end_ts']:.6f}"
                if q["upload_start_ts"] is not None
                else "n/a"
            )
            response_range = (
                f"{q['response_start_ts']:.6f}-{q['response_end_ts']:.6f}"
                if q["response_start_ts"] is not None
                and q["response_end_ts"] is not None
                else "n/a"
            )
            print(
                f"Query {q['id']}: upload {upload_range}s ({q['upload_bytes']} B) -> "
                f"response {response_range}s ({q['response_bytes']} B) confidence={q['confidence']}"
            )


if __name__ == "__main__":
    main()
