#!/usr/bin/env python3
"""
pcap_overview.py — Whole-file summary statistics for a PCAP/PCAPNG file.

Outputs protocol distribution, packet size stats, inter-arrival timing,
flow counts, and other characteristics useful for evaluating the capture
as a background (non-LLM) traffic source.

Usage:
    python pcap_overview.py <path_to_pcap> [--topn 20]

Requires: scapy, numpy
    pip install scapy numpy
"""

import argparse
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, DNS, Raw


# ──────────────────────────────────────────────────────────────────────
# Accumulators
# ──────────────────────────────────────────────────────────────────────

class PcapStats:
    """Collects running statistics in a single pass over the pcap."""

    def __init__(self):
        # Counts
        self.total_packets = 0
        self.total_bytes = 0

        # Per-protocol counters
        self.l3_proto = Counter()          # IPv4 / IPv6 / Other
        self.l4_proto = Counter()          # TCP / UDP / ICMP / Other
        self.l7_guess = Counter()          # rough app-layer guess

        # TCP flag distribution
        self.tcp_flags = Counter()

        # Packet sizes
        self.pkt_sizes: list[int] = []

        # Timestamps (epoch floats)
        self.timestamps: list[float] = []

        # Flow tracking  (5-tuple → packet count, byte count)
        self.flows: dict[tuple, dict] = defaultdict(
            lambda: {"packets": 0, "bytes": 0, "first": None, "last": None}
        )

        # Port counters (for top-N)
        self.src_ports = Counter()
        self.dst_ports = Counter()

        # TTL / Hop-limit values
        self.ttls: list[int] = []

    # ── packet handler ────────────────────────────────────────────────

    def ingest(self, pkt, ts: float):
        length = len(pkt)
        self.total_packets += 1
        self.total_bytes += length
        self.pkt_sizes.append(length)
        self.timestamps.append(ts)

        # --- L3 ---
        if pkt.haslayer(IP):
            self.l3_proto["IPv4"] += 1
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto_num = pkt[IP].proto
            self.ttls.append(pkt[IP].ttl)
        elif pkt.haslayer(IPv6):
            self.l3_proto["IPv6"] += 1
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            proto_num = pkt[IPv6].nh
            self.ttls.append(pkt[IPv6].hlim)
        else:
            self.l3_proto["Other"] += 1
            return  # can't do much more without IP

        # --- L4 ---
        src_port = dst_port = 0
        if pkt.haslayer(TCP):
            self.l4_proto["TCP"] += 1
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            self.tcp_flags[str(pkt[TCP].flags)] += 1
        elif pkt.haslayer(UDP):
            self.l4_proto["UDP"] += 1
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            self.l4_proto["ICMP"] += 1
        else:
            self.l4_proto[f"IPProto-{proto_num}"] += 1

        if src_port:
            self.src_ports[src_port] += 1
        if dst_port:
            self.dst_ports[dst_port] += 1

        # --- Flow key (canonical: lower IP first) ---
        fwd = (src_ip, dst_ip, src_port, dst_port, proto_num)
        rev = (dst_ip, src_ip, dst_port, src_port, proto_num)
        key = min(fwd, rev)  # canonical direction
        entry = self.flows[key]
        entry["packets"] += 1
        entry["bytes"] += length
        if entry["first"] is None:
            entry["first"] = ts
        entry["last"] = ts

        # --- L7 rough guess ---
        self._guess_app(pkt, src_port, dst_port)

    def _guess_app(self, pkt, sport, dport):
        """Heuristic app-layer classification — good enough for overview."""
        ports = {sport, dport}
        if pkt.haslayer(DNS):
            self.l7_guess["DNS"] += 1
        elif 443 in ports or 8443 in ports:
            self.l7_guess["HTTPS/TLS"] += 1
        elif 80 in ports or 8080 in ports:
            self.l7_guess["HTTP"] += 1
        elif 22 in ports:
            self.l7_guess["SSH"] += 1
        elif 53 in ports:
            self.l7_guess["DNS (port)"] += 1
        elif 123 in ports:
            self.l7_guess["NTP"] += 1
        elif 25 in ports or 465 in ports or 587 in ports:
            self.l7_guess["SMTP"] += 1
        elif 143 in ports or 993 in ports:
            self.l7_guess["IMAP"] += 1
        elif 110 in ports or 995 in ports:
            self.l7_guess["POP3"] += 1
        elif sport > 1023 and dport > 1023:
            self.l7_guess["Ephemeral↔Ephemeral"] += 1
        else:
            self.l7_guess["Other"] += 1


# ──────────────────────────────────────────────────────────────────────
# Reporting
# ──────────────────────────────────────────────────────────────────────

def pct(n, total):
    return f"{100 * n / total:6.2f}%" if total else "  N/A "


def print_counter(counter: Counter, total: int, topn: int, label: str):
    print(f"\n{'─' * 60}")
    print(f"  {label}")
    print(f"{'─' * 60}")
    for item, count in counter.most_common(topn):
        print(f"  {str(item):30s}  {count:>12,}  ({pct(count, total)})")


def report(s: PcapStats, topn: int):
    """Pretty-print the collected statistics."""
    ts = np.array(s.timestamps)
    sizes = np.array(s.pkt_sizes)
    ttls = np.array(s.ttls) if s.ttls else np.array([0])

    duration = ts[-1] - ts[0] if len(ts) > 1 else 0.0
    iats = np.diff(ts) if len(ts) > 1 else np.array([0.0])

    # ── Header ────────────────────────────────────────────────────────
    print("\n" + "═" * 60)
    print("  PCAP OVERVIEW")
    print("═" * 60)
    print(f"  Total packets     : {s.total_packets:>14,}")
    print(f"  Total bytes       : {s.total_bytes:>14,}  ({s.total_bytes / 1e6:.2f} MB)")
    print(f"  Capture duration  : {duration:>14.3f} s  ({duration / 60:.1f} min)")
    if duration > 0:
        print(f"  Avg throughput    : {s.total_bytes * 8 / duration / 1e6:>14.2f} Mbps")
        print(f"  Avg packet rate   : {s.total_packets / duration:>14.1f} pkt/s")
    print(f"  Unique flows      : {len(s.flows):>14,}")

    # ── Packet size distribution ──────────────────────────────────────
    print(f"\n{'─' * 60}")
    print("  PACKET SIZE (bytes)")
    print(f"{'─' * 60}")
    print(f"  Min / Max         : {sizes.min():>7,}  /  {sizes.max():>7,}")
    print(f"  Mean ± Std        : {sizes.mean():>7.1f}  ±  {sizes.std():>7.1f}")
    print(f"  Median (P50)      : {np.median(sizes):>7.1f}")
    print(f"  P5  / P95         : {np.percentile(sizes, 5):>7.1f}  /  {np.percentile(sizes, 95):>7.1f}")
    print(f"  P1  / P99         : {np.percentile(sizes, 1):>7.1f}  /  {np.percentile(sizes, 99):>7.1f}")

    # Size buckets
    buckets = [(0, 64), (65, 128), (129, 256), (257, 512),
               (513, 1024), (1025, 1500), (1501, 9000)]
    print("\n  Size buckets:")
    for lo, hi in buckets:
        n = int(np.sum((sizes >= lo) & (sizes <= hi)))
        if n > 0:
            print(f"    {lo:>5}–{hi:<5}  {n:>12,}  ({pct(n, s.total_packets)})")

    # ── Inter-arrival time ────────────────────────────────────────────
    print(f"\n{'─' * 60}")
    print("  INTER-ARRIVAL TIME (seconds)")
    print(f"{'─' * 60}")
    if len(iats) > 1:
        print(f"  Mean ± Std        : {iats.mean():.6f}  ±  {iats.std():.6f}")
        print(f"  Median            : {np.median(iats):.6f}")
        print(f"  P95 / P99         : {np.percentile(iats, 95):.6f}  /  {np.percentile(iats, 99):.6f}")
        print(f"  Max               : {iats.max():.6f}")
    else:
        print("  (not enough packets for IAT stats)")

    # ── TTL / Hop Limit ───────────────────────────────────────────────
    print(f"\n{'─' * 60}")
    print("  TTL / HOP LIMIT")
    print(f"{'─' * 60}")
    print(f"  Mean ± Std        : {ttls.mean():.1f}  ±  {ttls.std():.1f}")
    print(f"  Unique values     : {len(np.unique(ttls))}")
    ttl_counts = Counter(ttls.tolist())
    for val, cnt in ttl_counts.most_common(5):
        print(f"    TTL {int(val):>3d}          {cnt:>12,}  ({pct(cnt, len(ttls))})")

    # ── Protocol distributions ────────────────────────────────────────
    print_counter(s.l3_proto, s.total_packets, topn, "L3 PROTOCOL")
    print_counter(s.l4_proto, s.total_packets, topn, "L4 PROTOCOL")
    print_counter(s.l7_guess, s.total_packets, topn, "APPLICATION LAYER (heuristic)")
    print_counter(s.tcp_flags, s.l4_proto.get("TCP", 0), topn, "TCP FLAGS")

    # ── Top ports ─────────────────────────────────────────────────────
    print_counter(s.dst_ports, s.total_packets, topn, "TOP DESTINATION PORTS")
    print_counter(s.src_ports, s.total_packets, topn, "TOP SOURCE PORTS")

    # ── Flow-level summary ────────────────────────────────────────────
    print(f"\n{'─' * 60}")
    print("  FLOW-LEVEL SUMMARY")
    print(f"{'─' * 60}")
    flow_pkts = np.array([v["packets"] for v in s.flows.values()])
    flow_bytes = np.array([v["bytes"] for v in s.flows.values()])
    flow_dur = np.array([
        (v["last"] - v["first"]) for v in s.flows.values()
        if v["first"] is not None and v["last"] is not None
    ])

    print(f"  Flows             : {len(s.flows):>12,}")
    print(f"  Pkts/flow  mean   : {flow_pkts.mean():>12.1f}")
    print(f"  Pkts/flow  median : {np.median(flow_pkts):>12.1f}")
    print(f"  Pkts/flow  max    : {flow_pkts.max():>12,}")
    print(f"  Bytes/flow mean   : {flow_bytes.mean():>12.1f}")
    print(f"  Bytes/flow median : {np.median(flow_bytes):>12.1f}")
    if len(flow_dur) > 0:
        nonzero_dur = flow_dur[flow_dur > 0]
        if len(nonzero_dur) > 0:
            print(f"  Duration   mean   : {nonzero_dur.mean():>12.3f} s")
            print(f"  Duration   median : {np.median(nonzero_dur):>12.3f} s")
            print(f"  Duration   max    : {nonzero_dur.max():>12.3f} s")
        single_pkt_flows = int(np.sum(flow_pkts == 1))
        print(f"  Single-pkt flows  : {single_pkt_flows:>12,}  ({pct(single_pkt_flows, len(s.flows))})")

    # ── Elephant flows ────────────────────────────────────────────────
    print(f"\n{'─' * 60}")
    print(f"  TOP {min(10, len(s.flows))} ELEPHANT FLOWS (by bytes)")
    print(f"{'─' * 60}")
    sorted_flows = sorted(s.flows.items(), key=lambda kv: kv[1]["bytes"], reverse=True)
    for key, val in sorted_flows[:10]:
        src_ip, dst_ip, sp, dp, proto = key
        dur = val["last"] - val["first"] if val["first"] and val["last"] else 0
        print(f"  {src_ip}:{sp} ↔ {dst_ip}:{dp}  proto={proto}")
        print(f"      {val['packets']:>8,} pkts   {val['bytes']:>12,} bytes   {dur:.2f}s")

    print("\n" + "═" * 60)


# ──────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Single-pass PCAP overview for background-traffic evaluation."
    )
    parser.add_argument("pcap", type=str, help="Path to .pcap or .pcapng file")
    parser.add_argument("--topn", type=int, default=20,
                        help="How many entries to show in top-N tables (default: 20)")
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"ERROR: {pcap_path} not found", file=sys.stderr)
        sys.exit(1)

    stats = PcapStats()

    print(f"Reading {pcap_path} …")
    t0 = time.time()
    count = 0
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            ts = float(pkt.time)
            stats.ingest(pkt, ts)
            count += 1
            if count % 500_000 == 0:
                elapsed = time.time() - t0
                rate = count / elapsed
                print(f"  … {count:>12,} packets  ({rate:,.0f} pkt/s)", file=sys.stderr)

    elapsed = time.time() - t0
    print(f"Parsed {count:,} packets in {elapsed:.1f}s "
          f"({count / elapsed:,.0f} pkt/s)\n")

    report(stats, topn=args.topn)


if __name__ == "__main__":
    main()