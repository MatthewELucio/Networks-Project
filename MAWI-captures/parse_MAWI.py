#!/usr/bin/env python3
"""
High-performance MAWI parser + Firestore uploader.
Multiprocessing-enabled for large traces (~70M+ packets).
"""

import argparse
import tempfile
import os
import requests
import gzip
import dpkt
import socket
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from typing import Any, Dict, Iterable, List, Tuple, Optional
from collections import defaultdict
import ipaddress
import statistics

from google.cloud import firestore


# ============================================================
# Firestore Logic
# ============================================================

DEFAULT_PROJECT_ID = "networks-project-s26"
DEFAULT_COLLECTION = "parsed-flowlets"
FLOWLET_THRESHOLDS = [0.05, 0.1, 0.2]


def threshold_suffix(threshold: float) -> str:
    return f"{threshold:g}"

FlowletDict = Dict[str, Any]


def _default_flowlet_transform(flowlet: FlowletDict) -> FlowletDict:
    out = dict(flowlet)
    out.pop("inter_packet_times", None)
    out.pop("packet_sizes", None)
    traffic_class = out.pop("traffic_class", None)

    out["is_llm_prediction"] = bool(traffic_class == "llm")
    return out


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

    def write_capture(
        self,
        capture_id: str,
        flowlets: Iterable[FlowletDict],
    ) -> None:
        doc_ref = self._client.collection(self.collection_name).document(capture_id)
        payload = {"capture_id": capture_id}

        for idx, flowlet in enumerate(flowlets, start=1):
            key = _format_flowlet_key(idx)
            payload[key] = _default_flowlet_transform(flowlet)

        doc_ref.set(payload)


# ============================================================
# Download + Parsing
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
                packets.append({
                    "ts": float(ts),
                    "proto": str(proto),
                    "src_ip": src_ip,
                    "src_port": getattr(l4, "sport", None),
                    "dst_ip": dst_ip,
                    "dst_port": getattr(l4, "dport", None),
                    "length": len(buf),
                })

            except Exception:
                continue

    return packets


# ============================================================
# Flow Logic
# ============================================================

def is_private_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def infer_flow_direction(flow_key: Tuple) -> str:
    src, sport, dst, dport, _ = flow_key

    if is_private_ip(src) and not is_private_ip(dst):
        return "client_to_server"
    if is_private_ip(dst) and not is_private_ip(src):
        return "server_to_client"

    if dport == 443 and sport != 443:
        return "client_to_server"
    if sport == 443 and dport != 443:
        return "server_to_client"

    return "unknown"


def canonical_flow_key(pkt: Dict[str, Any]) -> Tuple:
    return (
        pkt["src_ip"] or "",
        pkt["src_port"] or 0,
        pkt["dst_ip"] or "",
        pkt["dst_port"] or 0,
        (pkt["proto"] or "").upper(),
    )


def split_flowlets(flow_pkts, threshold):
    if not flow_pkts:
        return []

    flowlets = []
    current = {
        "start_ts": flow_pkts[0]["ts"],
        "end_ts": flow_pkts[0]["ts"],
        "packets": 1,
        "bytes": flow_pkts[0]["length"],
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
                "bytes": pkt["length"],
                "pkts": [pkt],
            }
        else:
            current["end_ts"] = pkt["ts"]
            current["packets"] += 1
            current["bytes"] += pkt["length"]
            current["pkts"].append(pkt)

        last_ts = pkt["ts"]

    flowlets.append(current)
    return flowlets


def compute_packet_statistics(pkts):
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
        sorted_pkts[i]["ts"] - sorted_pkts[i - 1]["ts"]
        for i in range(1, len(sorted_pkts))
    ]

    packet_sizes = [p["length"] for p in sorted_pkts]

    return {
        "inter_packet_times": inter_packet_times,
        "inter_packet_time_mean": statistics.mean(inter_packet_times) if inter_packet_times else 0.0,
        "inter_packet_time_std": statistics.stdev(inter_packet_times) if len(inter_packet_times) > 1 else 0.0,
        "packet_sizes": packet_sizes,
        "packet_size_mean": statistics.mean(packet_sizes) if packet_sizes else 0.0,
        "packet_size_std": statistics.stdev(packet_sizes) if len(packet_sizes) > 1 else 0.0,
    }


# ============================================================
# Multiprocessing Worker
# ============================================================

def process_single_flow(args):
    flow_key, pkts, threshold, traffic_class, source_file = args

    src_ip, src_port, dst_ip, dst_port, proto = flow_key

    pkts_sorted = sorted(pkts, key=lambda x: x["ts"])
    direction = infer_flow_direction(flow_key)
    outgoing = direction == "client_to_server"
    direction_encoded = 1 if outgoing else -1

    flowlets = split_flowlets(pkts_sorted, threshold)

    results = []

    for idx, flowlet in enumerate(flowlets, start=1):
        stats = compute_packet_statistics(flowlet["pkts"])

        results.append({
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
            "direction": direction,
            "outgoing": outgoing,
            "direction_encoded": direction_encoded,
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
        })

    return results


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--max-packets", type=int, default=None)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmpdir:
        gz_path = os.path.join(tmpdir, "input.pcap.gz")

        print("Downloading...")
        download_file(args.url, gz_path)

        print("Parsing...")
        packets = parse_pcap_gz_to_packets(gz_path, args.max_packets)
        print(f"Parsed {len(packets)} packets")

        flows = defaultdict(list)
        for pkt in packets:
            flows[canonical_flow_key(pkt)].append(pkt)

        print(f"Total flows: {len(flows)}")
        print("Extracting flowlets (multiprocessing)...")

        cpu_count = multiprocessing.cpu_count()

        capture_id = os.path.basename(args.url).replace(".pcap.gz", "")

        client = ParsedFlowletFirestore()
        for threshold in FLOWLET_THRESHOLDS:
            flowlet_features = []
            with ProcessPoolExecutor(max_workers=cpu_count) as executor:
                results = executor.map(
                    process_single_flow,
                    [
                        (k, v, threshold, "non-llm", gz_path)
                        for k, v in flows.items()
                    ],
                )

                for r in results:
                    flowlet_features.extend(r)

            threshold_capture_id = f"{capture_id}_{threshold_suffix(threshold)}"
            print(f"Uploading {len(flowlet_features)} flowlets for threshold {threshold_suffix(threshold)}...")
            client.write_capture(threshold_capture_id, flowlet_features)

        print("Done.")


if __name__ == "__main__":
    main()