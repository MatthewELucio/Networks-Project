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
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple
import json
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

def init_mongodb_backend(db_name=DEFAULT_DB_NAME, collection_name=DEFAULT_COLLECTION):
    if _db_cloud is None:
        raise RuntimeError(
            "database_mongodb.py is not available. "
            "Ensure data-pipeline/flowlet-parsing/database_mongodb.py exists and is importable."
        )
    _db_cloud.init_database(None, db_name=db_name, collection=collection_name)


class ThresholdCaptureWriter:
    def __init__(self, capture_id: str, threshold: float, batch_size: int):
        self.base_capture_id = capture_id
        self.capture_id = capture_id
        self.threshold = threshold
        self.batch_size = batch_size
        self.buffered = 0
        self.total_written = 0
        self.part = 1
        self._db = _db_cloud.get_db_session()
        self._Capture = _db_cloud.Capture
        self._Flowlet = _db_cloud.Flowlet
        self._flowlets = []
        self._start_new_doc()

    def _start_new_doc(self):
        self.capture_id = f"{self.base_capture_id}_part_{self.part}"
        self._capture = self._Capture(
            file_path=self.capture_id,
            status="active",
            llm_ip_map=json.dumps({}),
            notes=f"Parallel MAWI Import (threshold={self.threshold}, part={self.part})",
        )
        self._db.add(self._capture)
        self._db.commit()
        self._flowlets = []

    def add_flowlet(self, flowlet: Dict[str, Any]) -> None:
        outgoing = flowlet.get("outgoing")
        direction_encoded = 1 if outgoing is True else (-1 if outgoing is False else 0)
        traffic_class = (flowlet.get("traffic_class") or "non_llm").replace("-", "_")
        flowlet_doc = self._Flowlet(
            capture_id=self._capture.id,
            src_ip=flowlet.get("src_ip"),
            src_port=flowlet.get("src_port"),
            dst_ip=flowlet.get("dst_ip"),
            dst_port=flowlet.get("dst_port"),
            protocol=flowlet.get("protocol"),
            flowlet_id=flowlet.get("flowlet_id", 0),
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
        self._flowlets.append(flowlet_doc)
        self.buffered += 1
        self.total_written += 1
        if self.buffered >= self.batch_size:
            self.flush()

    def flush(self) -> None:
        if self.buffered > 0:
            try:
                # Estimate BSON size: serialize flowlets and check size
                flowlets_dicts = [f.to_dict() for f in self._flowlets]
                payload = {
                    "file_path": self.capture_id,
                    "status": self._capture.status,
                    "llm_ip_map": json.loads(self._capture.llm_ip_map),
                    "notes": self._capture.notes,
                    "flowlets": flowlets_dicts,
                }
                import bson
                size = len(bson.BSON.encode(payload))
                if size > 16000000:
                    print(f"⚠️ Document size {size} exceeds 16MB, splitting to new part...")
                    self.part += 1
                    self._start_new_doc()
                    self.buffered = 0
                    return
                # Write/update document
                self._db._captures.replace_one({"_id": self.capture_id}, payload, upsert=True)
                self._flowlets = []
                self.buffered = 0
            except Exception as e:
                err_str = str(e)
                print(f"⚠️ Unexpected DB error: {err_str}")
                self._flowlets = []
                self.buffered = 0

    def finalize(self, status: str = "completed") -> None:
        self._capture.status = status
        self.flush()
        self._db.close()


@dataclass
class RunningStats:
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def add(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    def std(self) -> float:
        if self.count < 2:
            return 0.0
        return (self.m2 / (self.count - 1)) ** 0.5


class FlowletAccumulator:
    def __init__(self, first_packet: Dict[str, Any]):
        ts = first_packet["ts"]
        size = first_packet["length"]
        self.start_ts = ts
        self.end_ts = ts
        self.packet_count = 1
        self.total_bytes = size
        self.ipt_stats = RunningStats()
        self.size_stats = RunningStats()
        self.size_stats.add(float(size))

    def add_packet(self, packet: Dict[str, Any]) -> None:
        ts = packet["ts"]
        size = packet["length"]
        ipt = ts - self.end_ts
        self.ipt_stats.add(float(ipt))
        self.size_stats.add(float(size))
        self.end_ts = ts
        self.packet_count += 1
        self.total_bytes += size

    def to_flowlet_dict(self, flow_key: Tuple[str, int, str, int, str], flowlet_id: int) -> Dict[str, Any]:
        src, sport, dst, dport, proto = flow_key
        return {
            "src_ip": src,
            "src_port": sport,
            "dst_ip": dst,
            "dst_port": dport,
            "protocol": proto,
            "flowlet_id": flowlet_id,
            "traffic_class": "non-llm",
            "llm_name": None,
            "outgoing": (dport == 443),
            "start_ts": self.start_ts,
            "end_ts": self.end_ts,
            "duration": self.end_ts - self.start_ts,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "inter_packet_time_mean": self.ipt_stats.mean if self.ipt_stats.count > 0 else 0.0,
            "inter_packet_time_std": self.ipt_stats.std(),
            "packet_size_mean": self.size_stats.mean if self.size_stats.count > 0 else 0.0,
            "packet_size_std": self.size_stats.std(),
        }


class ThresholdFlowletProcessor:
    def __init__(self, threshold: float, writer: ThresholdCaptureWriter):
        self.threshold = threshold
        self.writer = writer
        self.active: Dict[Tuple[str, int, str, int, str], FlowletAccumulator] = {}
        self.flowlet_counts: Dict[Tuple[str, int, str, int, str], int] = {}

    def process_packet(self, packet: Dict[str, Any]) -> None:
        flow_key = (
            packet["src_ip"],
            packet["src_port"],
            packet["dst_ip"],
            packet["dst_port"],
            packet["proto"].upper(),
        )
        acc = self.active.get(flow_key)
        if acc is None:
            self.active[flow_key] = FlowletAccumulator(packet)
            return

        gap = packet["ts"] - acc.end_ts
        if gap > self.threshold:
            self._emit_flowlet(flow_key, acc)
            self.active[flow_key] = FlowletAccumulator(packet)
            return

        acc.add_packet(packet)

    def flush_inactive(self, current_ts: float) -> None:
        to_flush = []
        for flow_key, acc in self.active.items():
            if (current_ts - acc.end_ts) > self.threshold:
                to_flush.append(flow_key)

        for flow_key in to_flush:
            acc = self.active.pop(flow_key)
            self._emit_flowlet(flow_key, acc)

    def flush_all(self) -> None:
        for flow_key, acc in list(self.active.items()):
            self._emit_flowlet(flow_key, acc)
        self.active.clear()

    def _emit_flowlet(self, flow_key: Tuple[str, int, str, int, str], acc: FlowletAccumulator) -> None:
        next_id = self.flowlet_counts.get(flow_key, 0) + 1
        self.flowlet_counts[flow_key] = next_id
        self.writer.add_flowlet(acc.to_flowlet_dict(flow_key, next_id))

# --- Parsing Helpers ---
def download_file(url, out_path):
    # Use a realistic timeout for large MAWI files
    resp = requests.get(url, stream=True, timeout=120)
    resp.raise_for_status()
    with open(out_path, 'wb') as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)

def iter_pcap_gz_packets(gz_path: str, max_packets: int | None = None) -> Iterable[Dict[str, Any]]:
    with gzip.open(gz_path, 'rb') as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception:
            return

        for idx, (ts, buf) in enumerate(pcap):
            if max_packets and idx >= max_packets:
                return
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if isinstance(ip, dpkt.ip.IP):
                    src = socket.inet_ntoa(ip.src)
                    dst = socket.inet_ntoa(ip.dst)
                    proto = str(ip.p)
                elif isinstance(ip, dpkt.ip6.IP6):
                    src = socket.inet_ntop(socket.AF_INET6, ip.src)
                    dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
                    proto = str(ip.nxt)
                else:
                    continue

                yield {
                    "ts": float(ts),
                    "proto": proto,
                    "src_ip": src,
                    "src_port": int(getattr(ip.data, "sport", 0) or 0),
                    "dst_ip": dst,
                    "dst_port": int(getattr(ip.data, "dport", 0) or 0),
                    "length": len(buf),
                }
            except Exception:
                continue

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

def process_pipeline(url_template, max_packets, flowlets_per_doc):
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
        writers = None
        try:
            download_file(valid_url, gz_path)
            init_mongodb_backend()

            writers = {
                threshold: ThresholdCaptureWriter(
                    capture_id=f"{capture_id}_{threshold_suffix(threshold)}",
                    threshold=threshold,
                    batch_size=flowlets_per_doc,
                )
                for threshold in FLOWLET_THRESHOLDS
            }
            processors = {
                threshold: ThresholdFlowletProcessor(threshold=threshold, writer=writers[threshold])
                for threshold in FLOWLET_THRESHOLDS
            }


            parsed_packets = 0
            last_ts = None
            flowlet_counts = {threshold: 0 for threshold in FLOWLET_THRESHOLDS}

            for parsed_packets, packet in enumerate(iter_pcap_gz_packets(gz_path, max_packets), start=1):
                last_ts = packet["ts"]
                for threshold in FLOWLET_THRESHOLDS:
                    processors[threshold].process_packet(packet)

                # No packet-based chunking; flowlet-based chunking is handled in writer.flush()

            # After all packets, flush all remaining flowlets


            if parsed_packets == 0:
                print(f"❌ No packets parsed for {capture_id}")
                for threshold in FLOWLET_THRESHOLDS:
                    writers[threshold].finalize(status="failed")
                return False

            for threshold in FLOWLET_THRESHOLDS:
                processors[threshold].flush_all()
                writers[threshold].finalize(status="completed")
                print(
                    f"✅ Success: {capture_id}_{threshold_suffix(threshold)} "
                    f"(flowlets={writers[threshold].total_written:,})"
                )

            return True
        except Exception as e:
            print(f"❌ Error processing {capture_id}: {e}")
            if writers is not None:
                for threshold in FLOWLET_THRESHOLDS:
                    try:
                        writers[threshold].finalize(status="failed")
                    except Exception:
                        pass
            return False
        
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", help="YYYY-MM-DD", required=True)
    parser.add_argument("--end", help="YYYY-MM-DD", required=True)
    parser.add_argument("--step-days", type=int, default=1)
    parser.add_argument("--max-packets", type=int, default=2000)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--flowlets-per-doc", type=int, default=1000, help="Number of flowlets per Mongo document part")
    args = parser.parse_args()

    if args.flowlets_per_doc <= 0:
        raise ValueError("--flowlets-per-doc must be > 0")

    urls = generate_mawi_urls(args.start, args.end, args.step_days)

    with ThreadPoolExecutor(max_workers=args.workers) as threads:
        threads.map(lambda u: process_pipeline(u, args.max_packets, args.flowlets_per_doc), urls)

if __name__ == "__main__":
    main()