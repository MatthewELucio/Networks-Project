#!/usr/bin/env python3
import argparse
import tempfile
import os
import sys
import importlib.util
import requests
import gzip
import dpkt
import socket
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from typing import Any, Dict, List, Tuple, Optional
from collections import defaultdict
import ipaddress
import statistics
import json
import time
from datetime import datetime, timedelta
from pathlib import Path

# Import MongoDB backend used by live capture pipeline
DB_MODULE_DIR = Path(__file__).resolve().parents[1] / "data-pipeline" / "flowlet-parsing"
if str(DB_MODULE_DIR) not in sys.path:
    sys.path.append(str(DB_MODULE_DIR))

DB_MODULE_PATH = DB_MODULE_DIR / "database_mongodb.py"

if DB_MODULE_PATH.exists():
    _db_spec = importlib.util.spec_from_file_location("database_mongodb", DB_MODULE_PATH)
    if _db_spec and _db_spec.loader:
        _db_cloud = importlib.util.module_from_spec(_db_spec)
        sys.modules[_db_spec.name] = _db_cloud
        _db_spec.loader.exec_module(_db_cloud)
    else:
        _db_cloud = None
else:
    _db_cloud = None

# --- CONFIGURATION ---
DEFAULT_DB_NAME = "networks_project"
DEFAULT_COLLECTION = "captures"
MAWI_BASE_URL = "http://mawi.nezu.wide.ad.jp/mawi/samplepoint-F"
FLOWLET_THRESHOLDS = [0.05, 0.1, 0.2]


def threshold_suffix(threshold: float) -> str:
    return f"{threshold:g}"
# ============================================================
# MongoDB Logic (Synchronized with live_capture_to_db_mac.py style)
# ============================================================

class ParsedFlowletMongoDB:
    def __init__(self, db_name=DEFAULT_DB_NAME, collection_name=DEFAULT_COLLECTION):
        if _db_cloud is None:
            raise RuntimeError(
                "database_mongodb.py is not available. "
                "Ensure data-pipeline/flowlet-parsing/database_mongodb.py exists and is importable."
            )

        _db_cloud.init_database(None, db_name=db_name, collection=collection_name)
        self._db = _db_cloud.get_db_session()
        self._Capture = _db_cloud.Capture
        self._Flowlet = _db_cloud.Flowlet

    def write_capture(self, capture_id: str, flowlets: List[Dict[str, Any]]) -> None:
        print(f"  -> Preparing MongoDB payload for {len(flowlets)} flowlets...")

        capture = self._Capture(
            file_path=capture_id,
            status="completed",
            llm_ip_map=json.dumps({}),
            notes="Parallel MAWI Import",
        )
        self._db.add(capture)
        self._db.commit()

        for idx, flowlet in enumerate(flowlets, start=1):
            outgoing = flowlet.get("outgoing")
            direction_encoded = 1 if outgoing is True else (-1 if outgoing is False else 0)
            traffic_class = (flowlet.get("traffic_class") or "non_llm").replace("-", "_")

            self._db.add(
                self._Flowlet(
                    capture_id=capture.id,
                    src_ip=flowlet.get("src_ip"),
                    src_port=flowlet.get("src_port"),
                    dst_ip=flowlet.get("dst_ip"),
                    dst_port=flowlet.get("dst_port"),
                    protocol=flowlet.get("protocol"),
                    flowlet_id=flowlet.get("flowlet_id") or idx,
                    traffic_class=traffic_class,
                    llm_name=flowlet.get("llm_name"),
                    outgoing=outgoing,
                    direction_encoded=direction_encoded,
                    start_ts=flowlet.get("start_ts", 0.0),
                    end_ts=flowlet.get("end_ts", 0.0),
                    duration=flowlet.get("duration", 0.0),
                    packet_count=flowlet.get("packet_count", 0),
                    total_bytes=flowlet.get("total_bytes", 0),
                    inter_packet_time_mean=flowlet.get("inter_packet_time_mean"),
                    inter_packet_time_std=flowlet.get("inter_packet_time_std"),
                    packet_size_mean=flowlet.get("packet_size_mean"),
                    packet_size_std=flowlet.get("packet_size_std"),
                )
            )

        self._db.commit()
        print(f"  -> Uploaded MongoDB document to {DEFAULT_DB_NAME}/{DEFAULT_COLLECTION}/{capture_id}")

    def close(self):
        self._db.close()

# --- Parsing Helpers ---
def download_file(url, out_path):
    # Use a realistic timeout for large MAWI files
    resp = requests.get(url, stream=True, timeout=120)
    resp.raise_for_status()
    with open(out_path, 'wb') as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)

def parse_pcap_gz_to_packets(gz_path, max_packets=None):
    packets = []
    with gzip.open(gz_path, 'rb') as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except: return []
        for idx, (ts, buf) in enumerate(pcap):
            if max_packets and idx >= max_packets: break
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if isinstance(ip, dpkt.ip.IP):
                    src, dst, proto = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ip.p
                elif isinstance(ip, dpkt.ip6.IP6):
                    src, dst, proto = socket.inet_ntop(socket.AF_INET6, ip.src), socket.inet_ntop(socket.AF_INET6, ip.dst), ip.nxt
                else: continue
                
                packets.append({
                    "ts": float(ts), 
                    "proto": str(proto), 
                    "src_ip": src, 
                    "src_port": getattr(ip.data, "sport", 0),
                    "dst_ip": dst, 
                    "dst_port": getattr(ip.data, "dport", 0), 
                    "length": len(buf)
                })
            except: continue
    return packets

def process_single_flow(args):
    flow_key, pkts, threshold = args
    pkts_sorted = sorted(pkts, key=lambda x: x["ts"])
    src, sport, dst, dport, proto = flow_key
    
    flowlets = []
    if not pkts_sorted: return []
    curr = {"start_ts": pkts_sorted[0]["ts"], "end_ts": pkts_sorted[0]["ts"], "pkts": [pkts_sorted[0]]}
    for p in pkts_sorted[1:]:
        if p["ts"] - curr["end_ts"] > threshold:
            flowlets.append(curr)
            curr = {"start_ts": p["ts"], "end_ts": p["ts"], "pkts": [p]}
        else:
            curr["end_ts"] = p["ts"]; curr["pkts"].append(p)
    flowlets.append(curr)

    results = []
    for idx, fl in enumerate(flowlets, start=1):
        psizes = [p["length"] for p in fl["pkts"]]
        ipts = [fl["pkts"][i]["ts"] - fl["pkts"][i-1]["ts"] for i in range(1, len(fl["pkts"]))]
        
        # Structure exactly like database.py/live_capture_to_db.py
        results.append({
            "src_ip": src, 
            "src_port": sport, 
            "dst_ip": dst, 
            "dst_port": dport, 
            "protocol": proto,
            "flowlet_id": idx, 
            "traffic_class": "non-llm", 
            "llm_name": None,
            "outgoing": (dport == 443),
            "start_ts": fl["start_ts"], 
            "end_ts": fl["end_ts"],
            "duration": fl["end_ts"] - fl["start_ts"],
            "packet_count": len(psizes), 
            "total_bytes": sum(psizes),
            "inter_packet_time_mean": statistics.mean(ipts) if ipts else 0.0,
            "inter_packet_time_std": statistics.stdev(ipts) if len(ipts) > 1 else 0.0,
            "packet_size_mean": statistics.mean(psizes),
            "packet_size_std": statistics.stdev(psizes) if len(psizes) > 1 else 0.0,
        })
    return results

def generate_mawi_urls(start_str: str, end_str: str, step_days: int) -> List[str]:
    fmt = "%Y-%m-%d"
    start_dt = datetime.strptime(start_str, fmt)
    end_dt = datetime.strptime(end_str, fmt)
    urls = []
    current = start_dt
    while current <= end_dt:
        year = current.strftime("%Y")
        timestamp = current.strftime("%Y%m%d1400")
        urls.append(f"{MAWI_BASE_URL}/{year}/{timestamp}.pcap.gz")
        current += timedelta(days=step_days)
    return urls

def process_pipeline(url_template, max_packets):
    """
    Tries multiple timestamps (1400, 1359, 1401) to account for 
    sensor drift in the MAWI archive.
    """
    # 1. Generate potential candidate URLs for this specific day
    # We take the base URL and try a few common offsets
    base_url_dir = os.path.dirname(url_template)
    filename = os.path.basename(url_template)
    date_part = filename[:8] # e.g., "20210102"
    
    candidates = [
        f"{base_url_dir}/{date_part}1400.pcap.gz",
        f"{base_url_dir}/{date_part}1359.pcap.gz",
        f"{base_url_dir}/{date_part}1401.pcap.gz",
        f"{base_url_dir}/{date_part}1358.pcap.gz" # Occasionally seen
    ]

    valid_url = None
    capture_id = None

    # 2. Pre-flight check to find which one actually exists
    for candidate in candidates:
        try:
            check = requests.head(candidate, timeout=10)
            if check.status_code == 200:
                valid_url = candidate
                capture_id = os.path.basename(candidate).replace(".pcap.gz", "")
                print(f"🎯 Found valid trace: {capture_id}")
                break
        except Exception:
            continue

    if not valid_url:
        print(f"❌ Failed to find any trace for {date_part} (tried 1400, 1359, 1401, 1358)")
        return False

    # 3. Proceed with the found URL
    with tempfile.TemporaryDirectory() as tmpdir:
        gz_path = os.path.join(tmpdir, "input.pcap.gz")
        try:
            download_file(valid_url, gz_path)
            packets = parse_pcap_gz_to_packets(gz_path, max_packets)
            if not packets: return False

            flows = defaultdict(list)
            for p in packets: 
                key = (p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"], p["proto"].upper())
                flows[key].append(p)
            
            client = ParsedFlowletMongoDB()
            for threshold in FLOWLET_THRESHOLDS:
                flowlet_features = []
                with ProcessPoolExecutor() as executor:
                    map_args = [(k, v, threshold) for k, v in flows.items()]
                    for r in executor.map(process_single_flow, map_args): 
                        flowlet_features.extend(r)

                threshold_capture_id = f"{capture_id}_{threshold_suffix(threshold)}"
                client.write_capture(threshold_capture_id, flowlet_features)
                print(f"✅ Success: {threshold_capture_id}")
            client.close()
            return True
        except Exception as e:
            print(f"❌ Error processing {capture_id}: {e}")
            return False
        
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", help="YYYY-MM-DD", required=True)
    parser.add_argument("--end", help="YYYY-MM-DD", required=True)
    parser.add_argument("--step-days", type=int, default=1)
    parser.add_argument("--max-packets", type=int, default=2000)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    urls = generate_mawi_urls(args.start, args.end, args.step_days)

    with ThreadPoolExecutor(max_workers=args.workers) as threads:
        threads.map(lambda u: process_pipeline(u, args.max_packets), urls)

if __name__ == "__main__":
    main()