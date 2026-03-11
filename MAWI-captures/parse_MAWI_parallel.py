#!/usr/bin/env python3
import argparse
import tempfile
import os
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

# Import Firestore and dotenv
from google.cloud import firestore
from dotenv import load_dotenv

# Load credentials from .env if present
load_dotenv()

# --- CONFIGURATION ---
DEFAULT_PROJECT_ID = "networks-project-s26"
# CHANGED: Collection name matches your firebase.py / live logic
DEFAULT_COLLECTION = "parsed-flowlets" 
MAWI_BASE_URL = "http://mawi.nezu.wide.ad.jp/mawi/samplepoint-F"
# ============================================================
# Firestore Logic (Synchronized with live_capture_to_db.py style)
# ============================================================

class ParsedFlowletFirestore:
    def __init__(self, project_id=DEFAULT_PROJECT_ID, collection_name=DEFAULT_COLLECTION):
        self._client = firestore.Client(project=project_id)
        self.collection_name = collection_name

    def write_capture(self, capture_id: str, flowlets: List[Dict[str, Any]]) -> None:
        doc_ref = self._client.collection(self.collection_name).document(capture_id)
        
        # 1. Prepare the base document with metadata
        # Matching the structure expected by your React frontend
        payload = {
            "capture_id": capture_id,
            "file_path": f"MAWI_{capture_id}",
            "created_at": datetime.now().isoformat(),
            "status": "completed",
            "notes": "Parallel MAWI Import",
            "llm_ip_map": json.dumps({}), # Usually empty for MAWI
            "flow_count": len(flowlets)
        }

        # 2. Add flowlets as top-level fields (flowlet_000001, etc.)
        # This matches the "document-per-capture" style of your live script
        print(f"  -> Preparing payload for {len(flowlets)} flowlets...")
        for idx, flowlet in enumerate(flowlets, start=1):
            key = f"flowlet_{idx:06d}"
            payload[key] = flowlet

        # 3. Write the large document
        # NOTE: Firestore has a 1MB limit. If flow_count is very high, 
        # this will fail. We use a try-except to catch that.
        try:
            print(f"  -> Uploading document to {self.collection_name}/{capture_id}...")
            doc_ref.set(payload)
        except Exception as e:
            if "too large" in str(e).lower():
                print(f"❌ Error: Document {capture_id} exceeds 1MB Firestore limit. Reduce --max-packets.")
            else:
                raise e

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

def process_pipeline(url_template, threshold, max_packets):
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
            
            flowlet_features = []
            with ProcessPoolExecutor() as executor:
                map_args = [(k, v, threshold) for k, v in flows.items()]
                for r in executor.map(process_single_flow, map_args): 
                    flowlet_features.extend(r)
            
            # Use the actual capture_id found (e.g. 202101021359) for Firestore
            client = ParsedFlowletFirestore()
            client.write_capture(capture_id, flowlet_features)
            print(f"✅ Success: {capture_id}")
            return True
        except Exception as e:
            print(f"❌ Error processing {capture_id}: {e}")
            return False
        
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", help="YYYY-MM-DD", required=True)
    parser.add_argument("--end", help="YYYY-MM-DD", required=True)
    parser.add_argument("--step-days", type=int, default=1)
    parser.add_argument("--threshold", type=float, default=0.1)
    parser.add_argument("--max-packets", type=int, default=2000)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    urls = generate_mawi_urls(args.start, args.end, args.step_days)

    with ThreadPoolExecutor(max_workers=args.workers) as threads:
        threads.map(lambda u: process_pipeline(u, args.threshold, args.max_packets), urls)

if __name__ == "__main__":
    main()