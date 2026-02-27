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

# Import Firestore and dotenv just like your working firebase.py
from google.cloud import firestore
from dotenv import load_dotenv

# Load credentials from .env if present
load_dotenv()

# --- CONFIGURATION ---
DEFAULT_PROJECT_ID = "networks-project-s26"
DEFAULT_COLLECTION = "captures"  # Matches your live_capture_to_db logic
MAWI_BASE_URL = "http://mawi.wide.ad.jp/mawi/samplepoint-F"

# ============================================================
# Firestore Logic (Using your working firebase.py style)
# ============================================================

class ParsedFlowletFirestore:
    def __init__(self, project_id=DEFAULT_PROJECT_ID, collection_name=DEFAULT_COLLECTION):
        # This will now correctly pick up credentials from your environment/.env
        self._client = firestore.Client(project=project_id)
        self.collection_name = collection_name

    def write_capture(self, capture_id: str, flowlets: List[Dict[str, Any]]) -> None:
        doc_ref = self._client.collection(self.collection_name).document(capture_id)
        
        # 1. Write metadata
        doc_ref.set({
            "id": capture_id,
            "file_path": f"MAWI_{capture_id}",
            "created_at": datetime.now().isoformat(),
            "status": "completed",
            "flow_count": len(flowlets),
            "llm_ip_map": "{}"
        })

        flowlet_col = doc_ref.collection("flowlets")
        batch = self._client.batch()
        
        print(f"  -> Uploading {len(flowlets)} flowlets for {capture_id}...")

        for idx, flowlet in enumerate(flowlets, start=1):
            f_ref = flowlet_col.document(f"flowlet_{idx:06d}")
            batch.set(f_ref, flowlet)
            
            if idx % 500 == 0:
                # Commit and then wait a moment to avoid "Quota Exceeded"
                try:
                    batch.commit()
                    time.sleep(0.5) # Give Firestore a breather
                except Exception as e:
                    if "429" in str(e):
                        print(f"⚠️ Quota hit for {capture_id}. Retrying in 5s...")
                        time.sleep(5)
                        batch.commit()
                    else:
                        raise e
                batch = self._client.batch()

        # Final commit
        batch.commit()
        
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

# --- Parsing Helpers ---
def download_file(url, out_path):
    resp = requests.get(url, stream=True, timeout=60)
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
                packets.append({"ts": float(ts), "proto": str(proto), "src_ip": src, "src_port": getattr(ip.data, "sport", 0),
                                "dst_ip": dst, "dst_port": getattr(ip.data, "dport", 0), "length": len(buf)})
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
        results.append({
            "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport, "protocol": proto,
            "flowlet_id": idx, "traffic_class": "non-llm", "outgoing": (dport == 443),
            "packet_count": len(psizes), "total_bytes": sum(psizes),
            "packet_size_mean": statistics.mean(psizes),
            "packet_size_std": statistics.stdev(psizes) if len(psizes) > 1 else 0.0,
            "inter_packet_time_mean": statistics.mean(ipts) if ipts else 0.0,
            "inter_packet_time_std": statistics.stdev(ipts) if len(ipts) > 1 else 0.0,
        })
    return results
            
def process_pipeline(url, threshold, max_packets):
    capture_id = os.path.basename(url).replace(".pcap.gz", "")
    print(f"🟢 Starting Pipeline: {capture_id}")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        gz_path = os.path.join(tmpdir, "input.pcap.gz")
        try:
            resp = requests.get(url, stream=True, timeout=30)
            resp.raise_for_status()
            with open(gz_path, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)

            packets = parse_pcap_gz_to_packets(gz_path, max_packets)
            if not packets:
                print(f"⚠️ No packets found in {capture_id}")
                return False

            flows = defaultdict(list)
            for p in packets: flows[(p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"], p["proto"].upper())].append(p)
            
            flowlet_features = []
            with ProcessPoolExecutor() as executor:
                map_args = [(k, v, threshold) for k, v in flows.items()]
                for r in executor.map(process_single_flow, map_args): flowlet_features.extend(r)

            # Initialize Firestore with your project ID
            client = ParsedFlowletFirestore()
            client.write_capture(capture_id, flowlet_features)
            print(f"✅ Success: {capture_id}")
            return True

        except Exception as e:
            print(f"❌ Failed: {capture_id} | {e}")
            return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", help="Start date (YYYY-MM-DD)", required=True)
    parser.add_argument("--end", help="End date (YYYY-MM-DD)", required=True)
    parser.add_argument("--step-days", type=int, default=1, help="Fetch 1 file every N days (default: 1)")
    parser.add_argument("--threshold", type=float, default=0.1)
    parser.add_argument("--max-packets", type=int, default=50000)
    parser.add_argument("--workers", type=int, default=3)
    args = parser.parse_args()

    urls = generate_mawi_urls(args.start, args.end, args.step_days)
    print(f"🚀 Found {len(urls)} daily traces to process between {args.start} and {args.end}")

    with ThreadPoolExecutor(max_workers=args.workers) as threads:
        threads.map(lambda u: process_pipeline(u, args.threshold, args.max_packets), urls)

    print("🏁 Processing complete.")

if __name__ == "__main__":
    main()