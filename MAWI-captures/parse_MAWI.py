#!/usr/bin/env python3
# ROBS A LOT OF CODE so that it can be run independently of the repo.
"""
Self-contained MAWI parser + Firestore uploader.
No tcpdump. No .txt files. No firebase.py dependency.
"""

import argparse
import sys
import tempfile
import os
import requests
import gzip
import dpkt
import socket
from typing import Any, Dict, Iterable, List, Tuple, Optional

from google.cloud import firestore


# ============================================================
# Firestore Logic (inlined from firebase.py)
# ============================================================

DEFAULT_PROJECT_ID = "networks-project-s26"
DEFAULT_COLLECTION = "parsed-flowlets"

FlowletDict = Dict[str, Any]


def _default_flowlet_transform(flowlet: FlowletDict) -> FlowletDict:
    out = dict(flowlet)

    traffic_class = out.pop("traffic_class", None)
    out.pop("inter_packet_times", None)
    out.pop("packet_sizes", None)

    llm_name = out.get("llm_name")
    ground_truth_llm = out.get("ground_truth_llm")

    out["is_llm_prediction"] = bool(traffic_class == "llm")
    out["predicted_llm_name"] = llm_name
    out["ground_truth_llm_name"] = ground_truth_llm

    return out


def _next_flowlet_index(existing_fields: Dict[str, Any]) -> int:
    max_idx = 0
    for key in existing_fields.keys():
        if key.startswith("flowlet_"):
            suffix = key[len("flowlet_") :]
            if suffix.isdigit():
                max_idx = max(max_idx, int(suffix))
    return max_idx + 1


def _format_flowlet_key(index: int) -> str:
    return f"flowlet_{index:06d}"


class ParsedFlowletFirestore:
    def __init__(
        self,
        project_id: str = DEFAULT_PROJECT_ID,
        collection_name: str = DEFAULT_COLLECTION,
    ):
        self._client = firestore.Client(project=project_id)
        self.collection_name = collection_name

    def capture_ref(self, capture_id: str):
        return self._client.collection(self.collection_name).document(capture_id)

    def write_capture(
        self,
        capture_id: str,
        flowlets: Iterable[FlowletDict],
        overwrite: bool = True,
    ) -> None:
        doc_ref = self.capture_ref(capture_id)

        if overwrite:
            payload = {"capture_id": capture_id}
            for idx, flowlet in enumerate(flowlets, start=1):
                key = _format_flowlet_key(idx)
                payload[key] = _default_flowlet_transform(flowlet)
            doc_ref.set(payload)
            return

        snap = doc_ref.get()
        existing = snap.to_dict() if snap.exists else {}
        next_idx = _next_flowlet_index(existing)

        updates = {}
        for flowlet in flowlets:
            key = _format_flowlet_key(next_idx)
            updates[key] = _default_flowlet_transform(flowlet)
            next_idx += 1

        doc_ref.set(updates, merge=True)


# ============================================================
# PCAP Parsing Logic
# ============================================================

def download_file(url, out_path):
    resp = requests.get(url, stream=True)
    resp.raise_for_status()
    with open(out_path, 'wb') as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)


def parse_pcap_gz_to_packets(gz_path, max_packets=None):
    packets = []

    with gzip.open(gz_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        for idx, (ts, buf) in enumerate(pcap):
            if max_packets and idx >= max_packets:
                break

            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data

                if isinstance(ip, dpkt.ip.IP):
                    proto = ip.p
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                elif isinstance(ip, dpkt.ip6.IP6):
                    proto = ip.nxt
                    src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
                    dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)
                else:
                    continue

                l4 = ip.data
                src_port = getattr(l4, 'sport', None)
                dst_port = getattr(l4, 'dport', None)

                packets.append({
                    "ts": float(ts),
                    "proto": str(proto),
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "length": len(buf),
                })

            except Exception:
                continue

    return packets


# ============================================================
# Import Your Flowlet Logic
# ============================================================

import argparse
import json
import re
import ipaddress
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Any


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
        gap = sorted_pkts[i]["ts"] - sorted_pkts[i - 1]["ts"]
        inter_packet_times.append(gap)

    # Compute packet sizes
    packet_sizes = [p.get("length", 0) or 0 for p in sorted_pkts]

    # Calculate statistics
    import statistics

    ipt_mean = statistics.mean(inter_packet_times) if inter_packet_times else 0.0
    ipt_std = (
        statistics.stdev(inter_packet_times) if len(inter_packet_times) > 1 else 0.0
    )

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
    source_file: str,
    client_ip: Optional[str] = None,
    server_ip: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Extract detailed flowlet features including packet-level statistics.

    Returns list of flowlet feature dicts suitable for ML training.
    """
    flowlet_features = []

    for flow_key, pkts in flows.items():
        src_ip, src_port, dst_ip, dst_port, proto = flow_key

        # Sort packets by timestamp
        pkts_sorted = sorted(pkts, key=lambda x: x["ts"])

        # Infer flow direction
        direction = infer_flow_direction(
            flow_key, client_ip=client_ip, server_ip=server_ip
        )
        outgoing = direction == "client_to_server"
        direction_encoded = 1 if outgoing else -1

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
                # Direction features
                "direction": direction,
                "outgoing": outgoing,
                "direction_encoded": direction_encoded,
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

def group_packets_into_flows(
    packets: List[Dict[str, Any]], bidirectional: bool = False
) -> Dict[Tuple, List[Dict[str, Any]]]:
    flows = defaultdict(list)
    for pkt in packets:
        key = canonical_flow_key(pkt, bidirectional=bidirectional)
        flows[key].append(pkt)
    return flows

# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Download .pcap.gz, parse with dpkt, upload flowlets to Firestore."
    )
    parser.add_argument('url', help='URL to download .pcap.gz')
    parser.add_argument('--threshold', '-t', type=float, default=0.1)
    parser.add_argument('--max-packets', type=int, default=None)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmpdir:
        gz_path = os.path.join(tmpdir, 'input.pcap.gz')

        print(f"Downloading {args.url} ...")
        download_file(args.url, gz_path)

        print("Parsing pcap.gz...")
        packets = parse_pcap_gz_to_packets(
            gz_path,
            max_packets=args.max_packets
        )

        print(f"Parsed {len(packets)} packets")

        flows = group_packets_into_flows(packets, bidirectional=False)

        flowlet_features = extract_flowlet_features(
            flows,
            threshold=args.threshold,
            source_file=gz_path,
            traffic_class="non-llm"
        )

        capture_id = os.path.basename(args.url).replace('.pcap.gz', '')

        print(f"Uploading {len(flowlet_features)} flowlets...")
        client = ParsedFlowletFirestore()
        client.write_capture(capture_id, flowlet_features, overwrite=True)

        print("Upload complete.")


if __name__ == "__main__":
    main()