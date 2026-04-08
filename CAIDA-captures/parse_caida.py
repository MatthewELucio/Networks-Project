#!/usr/bin/env python3
"""
caida_to_mongodb.py
───────────────────
Parse a CAIDA Anonymized Internet Trace (e.g. equinix-nyc.dirA.20190117-130300.UTC.anon.pcap)
into flowlets at multiple inter-packet gap thresholds and push them to MongoDB.

Each MongoDB document holds at most --flowlets-per-doc flowlets (default 5 000) and is
named:  <monitor>_<direction>_<datetime>_<threshold>_part_<N>

Usage
─────
  python caida_to_mongodb.py \
      --pcap /data/equinix-nyc.dirA.20190117-130300.UTC.anon.pcap

  # Or with options:
  python caida_to_mongodb.py \
      --pcap /data/equinix-nyc.dirA.20190117-130300.UTC.anon.pcap \
      --max-packets 500000 \
      --flowlets-per-doc 5000 \
      --min-packets 3 \
      --db-name networks_project \
      --collection captures
"""

import argparse
import gzip
import importlib.util
import json
import os
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

import dpkt

# ── Import shared MongoDB backend (same module the live-capture pipeline uses) ──
DB_MODULE_DIR = Path(__file__).resolve().parents[1] / "data-pipeline" / "flowlet-parsing"
if str(DB_MODULE_DIR) not in sys.path:
    sys.path.append(str(DB_MODULE_DIR))

DB_MODULE_PATH = DB_MODULE_DIR / "database_mongodb.py"

_db_cloud = None
if DB_MODULE_PATH.exists():
    try:
        _db_spec = importlib.util.spec_from_file_location("database_mongodb", DB_MODULE_PATH)
        if _db_spec and _db_spec.loader:
            _db_cloud = importlib.util.module_from_spec(_db_spec)
            sys.modules[_db_spec.name] = _db_cloud
            _db_spec.loader.exec_module(_db_cloud)
        else:
            print(f"⚠️  Could not create module spec from {DB_MODULE_PATH}", flush=True)
    except Exception as exc:
        print(f"⚠️  Failed to import database_mongodb: {exc}", flush=True)
        _db_cloud = None
else:
    print(f"⚠️  DB module not found at {DB_MODULE_PATH}", flush=True)

# ── Configuration ────────────────────────────────────────────────────────────
DEFAULT_DB_NAME = "networks_project"
DEFAULT_COLLECTION = "captures"
FLOWLET_THRESHOLDS = [0.05, 0.1, 0.2]
DEFAULT_FLOWLETS_PER_DOC = 5000
DEFAULT_MIN_PACKETS = 3
# How often (in packets) to flush idle flows to keep memory bounded
IDLE_FLUSH_INTERVAL = 200_000

# dpkt data-link type constants
DLT_NULL = 0
DLT_EN10MB = 1       # Ethernet
DLT_RAW = 101        # Raw IP (CAIDA equinix traces)
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_IPV6 = 229


def threshold_suffix(threshold: float) -> str:
    return f"{threshold:g}"


# ── CAIDA filename metadata parser ──────────────────────────────────────────

@dataclass
class CaidaMeta:
    """Metadata extracted from a CAIDA anonymised trace filename."""
    monitor: str          # e.g. "equinix-nyc"
    direction: str        # e.g. "dirA"
    datetime_str: str     # e.g. "20190117-130300"
    timezone: str         # e.g. "UTC"
    is_anon: bool         # True when "anon" appears in the stem
    raw_stem: str         # full stem for fallback labelling

    @property
    def label(self) -> str:
        """Human-readable label used in notes / capture_id prefix."""
        return f"{self.monitor}_{self.direction}_{self.datetime_str}"

    def notes_dict(self) -> Dict[str, Any]:
        return {
            "source": "CAIDA",
            "monitor": self.monitor,
            "direction": self.direction,
            "datetime": self.datetime_str,
            "timezone": self.timezone,
            "anonymised": self.is_anon,
        }


def parse_caida_filename(path: str) -> CaidaMeta:
    """
    Parse a CAIDA trace filename such as:
        equinix-nyc.dirA.20190117-130300.UTC.anon.pcap(.gz)
    into structured metadata.
    """
    stem = Path(path).name
    for ext in (".gz", ".pcap", ".pcap.gz"):
        if stem.endswith(ext):
            stem = stem[: -len(ext)]

    parts = stem.split(".")
    monitor = parts[0] if len(parts) > 0 else "unknown"
    direction = parts[1] if len(parts) > 1 else "unknown"
    datetime_str = parts[2] if len(parts) > 2 else "unknown"
    timezone = parts[3] if len(parts) > 3 else "UTC"
    is_anon = "anon" in parts

    return CaidaMeta(
        monitor=monitor,
        direction=direction,
        datetime_str=datetime_str,
        timezone=timezone,
        is_anon=is_anon,
        raw_stem=stem,
    )


# ── MongoDB helpers ──────────────────────────────────────────────────────────

def init_mongodb_backend(db_name: str = DEFAULT_DB_NAME,
                         collection_name: str = DEFAULT_COLLECTION):
    if _db_cloud is None:
        raise RuntimeError(
            "database_mongodb.py is not available. "
            "Ensure data-pipeline/flowlet-parsing/database_mongodb.py exists and is importable."
        )
    _db_cloud.init_database(None, db_name=db_name, collection=collection_name)


class ThresholdCaptureWriter:
    """
    Buffers flowlets and writes them to MongoDB in documents of at most
    `batch_size` flowlets.  Documents are created lazily – only when
    flowlets actually need to be written – so no empty orphan docs are left.
    """

    def __init__(self, capture_id: str, threshold: float, batch_size: int,
                 caida_meta: CaidaMeta):
        self.base_capture_id = capture_id
        self.capture_id = capture_id
        self.threshold = threshold
        self.batch_size = batch_size
        self.caida_meta = caida_meta
        self.buffered = 0
        self.total_written = 0
        self.part = 1

        self._db = _db_cloud.get_db_session()
        self._Flowlet = _db_cloud.Flowlet
        self._flowlets: list = []

    # ── internal ──

    def _doc_id(self) -> str:
        return f"{self.base_capture_id}_part_{self.part}"

    def _notes_str(self) -> str:
        meta = self.caida_meta.notes_dict()
        meta["threshold"] = self.threshold
        meta["part"] = self.part
        return json.dumps(meta)

    # ── public API ──

    def add_flowlet(self, flowlet: Dict[str, Any]) -> None:
        outgoing = flowlet.get("outgoing")
        direction_encoded = 1 if outgoing is True else (-1 if outgoing is False else 0)
        traffic_class = (flowlet.get("traffic_class") or "non_llm").replace("-", "_")

        flowlet_doc = self._Flowlet(
            capture_id=self._doc_id(),
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
        """Write the current batch to MongoDB as a single document, then advance the part counter."""
        if self.buffered == 0:
            return

        doc_id = self._doc_id()
        try:
            flowlets_dicts = [f.to_dict() for f in self._flowlets]
            payload = {
                "_id": doc_id,
                "file_path": doc_id,
                "status": "active",
                "llm_ip_map": {},
                "notes": self._notes_str(),
                "flowlets": flowlets_dicts,
            }

            # Guard against the 16 MB BSON limit
            try:
                import bson
                size = len(bson.BSON.encode(payload))
                if size > 16_000_000:
                    print(f"⚠️  Document {doc_id} is {size / 1e6:.1f} MB – "
                          "splitting to new part", flush=True)
                    half = len(self._flowlets) // 2
                    second_half = self._flowlets[half:]
                    self._flowlets = self._flowlets[:half]
                    self.buffered = len(self._flowlets)
                    self.flush()
                    self._flowlets = second_half
                    self.buffered = len(second_half)
                    self.flush()
                    return
            except ImportError:
                pass  # bson not installed; skip size check

            self._db._captures.replace_one(
                {"_id": doc_id}, payload, upsert=True
            )
            print(f"   💾 Wrote {doc_id} ({len(flowlets_dicts):,} flowlets)", flush=True)

            self._flowlets = []
            self.buffered = 0
            # Advance part counter — next batch will get a new doc_id
            self.part += 1

        except Exception as exc:
            print(f"⚠️  DB error while flushing {doc_id}: {exc}", flush=True)
            self._flowlets = []
            self.buffered = 0

    def finalize(self, status: str = "completed") -> None:
        """Flush remaining flowlets and mark the last written document as completed."""
        self.flush()

        # The last successfully written doc is part - 1 (flush increments after writing)
        last_written_part = self.part - 1
        if last_written_part >= 1:
            last_doc_id = f"{self.base_capture_id}_part_{last_written_part}"
            try:
                self._db._captures.update_one(
                    {"_id": last_doc_id},
                    {"$set": {"status": status}},
                )
            except Exception as exc:
                print(f"⚠️  Could not set status on {last_doc_id}: {exc}", flush=True)

        self._db.close()


# ── Running statistics (Welford's online algorithm) ─────────────────────────

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


# ── Flowlet accumulation & processing ───────────────────────────────────────

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
        self.ipt_stats.add(float(ts - self.end_ts))
        self.size_stats.add(float(size))
        self.end_ts = ts
        self.packet_count += 1
        self.total_bytes += size

    def to_flowlet_dict(self, flow_key: Tuple[str, int, str, int, str],
                        flowlet_id: int) -> Dict[str, Any]:
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
            "inter_packet_time_mean": (self.ipt_stats.mean
                                       if self.ipt_stats.count > 0 else 0.0),
            "inter_packet_time_std": self.ipt_stats.std(),
            "packet_size_mean": (self.size_stats.mean
                                 if self.size_stats.count > 0 else 0.0),
            "packet_size_std": self.size_stats.std(),
        }


class ThresholdFlowletProcessor:
    def __init__(self, threshold: float, writer: ThresholdCaptureWriter,
                 min_packets: int = DEFAULT_MIN_PACKETS):
        self.threshold = threshold
        self.writer = writer
        self.min_packets = min_packets
        self.active: Dict[Tuple[str, int, str, int, str], FlowletAccumulator] = {}
        self.flowlet_counts: Dict[Tuple[str, int, str, int, str], int] = {}
        self.skipped_small = 0  # count of flowlets dropped by min_packets filter

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
        to_flush = [k for k, acc in self.active.items()
                    if (current_ts - acc.end_ts) > self.threshold]
        for flow_key in to_flush:
            acc = self.active.pop(flow_key)
            self._emit_flowlet(flow_key, acc)

    def flush_all(self) -> None:
        for flow_key, acc in list(self.active.items()):
            self._emit_flowlet(flow_key, acc)
        self.active.clear()

    def _emit_flowlet(self, flow_key: Tuple[str, int, str, int, str],
                      acc: FlowletAccumulator) -> None:
        # ── min-packets filter: drop keep-alives and tiny flowlets ──
        if acc.packet_count < self.min_packets:
            self.skipped_small += 1
            return

        next_id = self.flowlet_counts.get(flow_key, 0) + 1
        self.flowlet_counts[flow_key] = next_id
        self.writer.add_flowlet(acc.to_flowlet_dict(flow_key, next_id))


# ── Pcap iteration ──────────────────────────────────────────────────────────

def _parse_ip_layer(buf: bytes, datalink: int):
    """
    Extract the IP layer from a raw pcap buffer, handling different link types.

    CAIDA equinix traces use DLT_RAW (101) — packets start directly with the
    IP header, not an Ethernet frame.  This was the cause of the original bug
    where only ~15 packets parsed from a 2 GB file.

    Returns (ip_layer, buf_len) or (None, 0) on failure.
    """
    try:
        if datalink == DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            return eth.data, len(buf)

        elif datalink in (DLT_RAW, DLT_IPV4):
            # Raw IP – inspect version nibble
            if len(buf) == 0:
                return None, 0
            version = (buf[0] >> 4) & 0xF
            if version == 4:
                return dpkt.ip.IP(buf), len(buf)
            elif version == 6:
                return dpkt.ip6.IP6(buf), len(buf)
            return None, 0

        elif datalink == DLT_IPV6:
            return dpkt.ip6.IP6(buf), len(buf)

        elif datalink == DLT_NULL:
            # BSD loopback – 4-byte family header then IP
            if len(buf) < 5:
                return None, 0
            family = int.from_bytes(buf[:4], byteorder="little")
            ip_buf = buf[4:]
            if family == 2:
                return dpkt.ip.IP(ip_buf), len(buf)
            elif family in (24, 28, 30):  # AF_INET6 varies by OS
                return dpkt.ip6.IP6(ip_buf), len(buf)
            return None, 0

        elif datalink == DLT_LINUX_SLL:
            if len(buf) < 16:
                return None, 0
            proto = int.from_bytes(buf[14:16], byteorder="big")
            ip_buf = buf[16:]
            if proto == 0x0800:
                return dpkt.ip.IP(ip_buf), len(buf)
            elif proto == 0x86DD:
                return dpkt.ip6.IP6(ip_buf), len(buf)
            return None, 0

        else:
            # Unknown – try Ethernet as last resort
            eth = dpkt.ethernet.Ethernet(buf)
            return eth.data, len(buf)

    except Exception:
        return None, 0


def iter_pcap_packets(pcap_path: str,
                      max_packets: Optional[int] = None) -> Iterable[Dict[str, Any]]:
    """
    Yield packet dicts from a pcap or pcap.gz file.
    Detects the data-link type so it works with raw IP (CAIDA), Ethernet, etc.
    """
    opener = gzip.open if pcap_path.endswith(".gz") else open
    with opener(pcap_path, "rb") as fh:
        try:
            pcap = dpkt.pcap.Reader(fh)
        except Exception as exc:
            print(f"❌ Could not open pcap: {exc}", flush=True)
            return

        datalink = pcap.datalink()
        dl_names = {
            DLT_NULL: "DLT_NULL (BSD loopback)",
            DLT_EN10MB: "DLT_EN10MB (Ethernet)",
            DLT_RAW: "DLT_RAW (raw IP)",
            DLT_LINUX_SLL: "DLT_LINUX_SLL (Linux cooked)",
            DLT_IPV4: "DLT_IPV4",
            DLT_IPV6: "DLT_IPV6",
        }
        dl_label = dl_names.get(datalink, f"unknown ({datalink})")
        print(f"   Link type   : {dl_label}", flush=True)

        parse_errors = 0
        for idx, (ts, buf) in enumerate(pcap):
            if max_packets is not None and idx >= max_packets:
                return
            try:
                ip_layer, buf_len = _parse_ip_layer(buf, datalink)
                if ip_layer is None:
                    parse_errors += 1
                    continue

                if isinstance(ip_layer, dpkt.ip.IP):
                    src = socket.inet_ntoa(ip_layer.src)
                    dst = socket.inet_ntoa(ip_layer.dst)
                    proto = str(ip_layer.p)
                elif isinstance(ip_layer, dpkt.ip6.IP6):
                    src = socket.inet_ntop(socket.AF_INET6, ip_layer.src)
                    dst = socket.inet_ntop(socket.AF_INET6, ip_layer.dst)
                    proto = str(ip_layer.nxt)
                else:
                    parse_errors += 1
                    continue

                yield {
                    "ts": float(ts),
                    "proto": proto,
                    "src_ip": src,
                    "src_port": int(getattr(ip_layer.data, "sport", 0) or 0),
                    "dst_ip": dst,
                    "dst_port": int(getattr(ip_layer.data, "dport", 0) or 0),
                    "length": buf_len,
                }
            except Exception:
                parse_errors += 1
                continue

        if parse_errors > 0:
            print(f"   ⚠️  {parse_errors:,} packets could not be parsed", flush=True)


# ── Main pipeline ───────────────────────────────────────────────────────────

def process_caida_file(pcap_path: str,
                       max_packets: Optional[int],
                       flowlets_per_doc: int,
                       min_packets: int,
                       db_name: str,
                       collection: str) -> bool:
    """
    End-to-end: parse CAIDA pcap → flowlets → MongoDB.
    Returns True on success.
    """
    if not os.path.isfile(pcap_path):
        print(f"❌ File not found: {pcap_path}", flush=True)
        return False

    meta = parse_caida_filename(pcap_path)
    file_size_mb = os.path.getsize(pcap_path) / (1024 * 1024)
    print(f"📂 CAIDA trace : {meta.raw_stem}", flush=True)
    print(f"   Monitor     : {meta.monitor}", flush=True)
    print(f"   Direction   : {meta.direction}", flush=True)
    print(f"   Timestamp   : {meta.datetime_str} {meta.timezone}", flush=True)
    print(f"   Anonymised  : {meta.is_anon}", flush=True)
    print(f"   File size   : {file_size_mb:,.1f} MB", flush=True)
    print(f"   Thresholds  : {FLOWLET_THRESHOLDS}", flush=True)
    print(f"   Flowlets/doc: {flowlets_per_doc}", flush=True)
    print(f"   Min packets : {min_packets} (flowlets with fewer are dropped)", flush=True)
    print(flush=True)

    init_mongodb_backend(db_name=db_name, collection_name=collection)

    capture_prefix = meta.label

    writers = {
        t: ThresholdCaptureWriter(
            capture_id=f"{capture_prefix}_{threshold_suffix(t)}",
            threshold=t,
            batch_size=flowlets_per_doc,
            caida_meta=meta,
        )
        for t in FLOWLET_THRESHOLDS
    }
    processors = {
        t: ThresholdFlowletProcessor(
            threshold=t,
            writer=writers[t],
            min_packets=min_packets,
        )
        for t in FLOWLET_THRESHOLDS
    }

    parsed = 0
    try:
        for parsed, packet in enumerate(
            iter_pcap_packets(pcap_path, max_packets), start=1
        ):
            for t in FLOWLET_THRESHOLDS:
                processors[t].process_packet(packet)

            # Periodically flush idle flows to keep memory bounded
            if parsed % IDLE_FLUSH_INTERVAL == 0:
                ts_now = packet["ts"]
                for t in FLOWLET_THRESHOLDS:
                    processors[t].flush_inactive(ts_now)
                print(f"   … {parsed:,} packets processed, flushed idle flows", flush=True)

        if parsed == 0:
            print("❌ No packets parsed – check link type and file integrity", flush=True)
            return False

        # Flush remaining active flows
        for t in FLOWLET_THRESHOLDS:
            processors[t].flush_all()
            writers[t].finalize(status="completed")
            print(
                f"✅ {capture_prefix}_{threshold_suffix(t)}  –  "
                f"{writers[t].total_written:,} flowlets in "
                f"{writers[t].part - 1} doc(s)  "
                f"({processors[t].skipped_small:,} dropped < {min_packets} pkts)",
                flush=True,
            )

        print(f"\n🏁 Done – {parsed:,} packets parsed across all thresholds.", flush=True)
        return True

    except KeyboardInterrupt:
        print("\n⚠️  Interrupted – finalising partial data …", flush=True)
        for t in FLOWLET_THRESHOLDS:
            processors[t].flush_all()
            writers[t].finalize(status="interrupted")
        return False

    except Exception as exc:
        import traceback
        traceback.print_exc()
        print(f"❌ Error: {exc}", flush=True)
        for t in FLOWLET_THRESHOLDS:
            try:
                writers[t].finalize(status="failed")
            except Exception:
                pass
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Parse a CAIDA anonymised pcap into flowlets and push to MongoDB."
    )
    parser.add_argument(
        "--pcap", required=True,
        help="Path to the CAIDA .pcap or .pcap.gz file "
             "(e.g. equinix-nyc.dirA.20190117-130300.UTC.anon.pcap)",
    )
    parser.add_argument(
        "--max-packets", type=int, default=None,
        help="Cap the number of packets to parse (default: entire file)",
    )
    parser.add_argument(
        "--flowlets-per-doc", type=int, default=DEFAULT_FLOWLETS_PER_DOC,
        help=f"Max flowlets per MongoDB document (default {DEFAULT_FLOWLETS_PER_DOC})",
    )
    parser.add_argument(
        "--min-packets", type=int, default=DEFAULT_MIN_PACKETS,
        help=f"Minimum packet count per flowlet; smaller flowlets are dropped "
             f"(default {DEFAULT_MIN_PACKETS}, set to 1 to keep all)",
    )
    parser.add_argument(
        "--db-name", default=DEFAULT_DB_NAME,
        help=f"MongoDB database name (default '{DEFAULT_DB_NAME}')",
    )
    parser.add_argument(
        "--collection", default=DEFAULT_COLLECTION,
        help=f"MongoDB collection name (default '{DEFAULT_COLLECTION}')",
    )
    args = parser.parse_args()

    if args.flowlets_per_doc <= 0:
        raise ValueError("--flowlets-per-doc must be > 0")
    if args.min_packets < 1:
        raise ValueError("--min-packets must be >= 1")

    success = process_caida_file(
        pcap_path=args.pcap,
        max_packets=args.max_packets,
        flowlets_per_doc=args.flowlets_per_doc,
        min_packets=args.min_packets,
        db_name=args.db_name,
        collection=args.collection,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()