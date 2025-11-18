#!/usr/bin/env python3
"""parse_flowlets.py

Read a tcpdump-style text capture (the project's `capture_*.txt`) and
produce flows (5-tuples) and flowlets split by an inter-packet-gap threshold.

Usage: python3 parse_flowlets.py input.txt --threshold 0.1 --bidirectional --output out.json
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, date
from typing import Dict, List, Optional, Tuple, Any

# Regexes
TS_LINE_RE = re.compile(r'^(?P<ts>\d{2}:\d{2}:\d{2}\.\d+)\s+IP.*proto\s+(?P<proto>\w+)', re.IGNORECASE)
ADDR_LINE_RE = re.compile(
    r'^\s*(?P<src>\d+\.\d+\.\d+\.\d+)(?:\.(?P<sport>\d+))?\s*>\s*(?P<dst>\d+\.\d+\.\d+\.\d+)(?:\.(?P<dport>\d+))?:\s*(?P<rest>.*)$'
)
LENGTH_RE = re.compile(r'length\s+(?P<len>\d+)', re.IGNORECASE)


def ts_to_seconds(ts_str: str) -> float:
    """Convert hh:mm:ss.sss to seconds since midnight as float."""
    h, m, s = ts_str.split(':')
    return int(h) * 3600 + int(m) * 60 + float(s)


def parse_capture_text(path: str) -> List[Dict[str, Any]]:
    """Parse the capture text and return list of packet dicts.

    Each packet dict contains: ts (float seconds), proto, src_ip, src_port (int|None),
    dst_ip, dst_port (int|None), length (int|None), raw_lines (2-line tuple).
    """
    packets = []
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]

    i = 0
    while i < len(lines):
        line = lines[i]
        m = TS_LINE_RE.match(line)
        if m:
            ts_str = m.group('ts')
            proto = m.group('proto').upper()
            ts = ts_to_seconds(ts_str)
            # look ahead for address line
            addr_line = None
            if i + 1 < len(lines):
                addr_line = lines[i + 1]

            src = dst = sport = dport = None
            length = None
            if addr_line:
                ma = ADDR_LINE_RE.match(addr_line)
                if ma:
                    src = ma.group('src')
                    dst = ma.group('dst')
                    sport = ma.group('sport')
                    dport = ma.group('dport')
                    # try to get length from the addr line
                    ml = LENGTH_RE.search(addr_line)
                    if ml:
                        length = int(ml.group('len'))
                else:
                    # fallback: try to find any length on the next line
                    ml = LENGTH_RE.search(addr_line)
                    if ml:
                        length = int(ml.group('len'))

            # also try length from the TS line if not found
            if length is None:
                ml2 = LENGTH_RE.search(line)
                if ml2:
                    length = int(ml2.group('len'))

            pkt = {
                'ts': ts,
                'proto': proto,
                'src_ip': src,
                'src_port': int(sport) if sport else None,
                'dst_ip': dst,
                'dst_port': int(dport) if dport else None,
                'length': length,
                'raw': (line, addr_line) if addr_line is not None else (line, None),
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


def canonical_flow_key(pkt: Dict[str, Any], bidirectional: bool = False) -> Tuple:
    """Return a flow key tuple (src, sport, dst, dport, proto).

    If bidirectional is True the tuple is ordered so both directions map to same key.
    """
    src = pkt['src_ip'] or ''
    dst = pkt['dst_ip'] or ''
    sport = pkt['src_port'] or 0
    dport = pkt['dst_port'] or 0
    proto = (pkt['proto'] or '').upper()
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


def group_packets_into_flows(packets: List[Dict[str, Any]], bidirectional: bool = False) -> Dict[Tuple, List[Dict[str, Any]]]:
    flows = defaultdict(list)
    for pkt in packets:
        key = canonical_flow_key(pkt, bidirectional=bidirectional)
        flows[key].append(pkt)
    return flows


def split_flowlets(flow_pkts: List[Dict[str, Any]], threshold: float = 0.1) -> List[Dict[str, Any]]:
    """Split a list of packets (one flow) into flowlets by inter-packet gap threshold (seconds).

    Returns list of flowlets with keys: start_ts, end_ts, packets (count), bytes, pkts (list of pkts)
    """
    if not flow_pkts:
        return []

    flowlets = []
    current = {
        'start_ts': flow_pkts[0]['ts'],
        'end_ts': flow_pkts[0]['ts'],
        'packets': 1,
        'bytes': flow_pkts[0].get('length') or 0,
        'pkts': [flow_pkts[0]],
    }

    last_ts = flow_pkts[0]['ts']
    for pkt in flow_pkts[1:]:
        delta = pkt['ts'] - last_ts
        if delta > threshold:
            flowlets.append(current)
            current = {
                'start_ts': pkt['ts'],
                'end_ts': pkt['ts'],
                'packets': 1,
                'bytes': pkt.get('length') or 0,
                'pkts': [pkt],
            }
        else:
            current['end_ts'] = pkt['ts']
            current['packets'] += 1
            current['bytes'] += pkt.get('length') or 0
            current['pkts'].append(pkt)
        last_ts = pkt['ts']

    flowlets.append(current)
    return flowlets


def build_summary(flows: Dict[Tuple, List[Dict[str, Any]]], threshold: float, bidirectional: bool) -> Dict[str, Any]:
    out = {
        'flows_count': len(flows),
        'threshold': threshold,
        'bidirectional': bidirectional,
        'flows': [],
    }

    for key, pkts in flows.items():
        # packets should already be in chronological order
        pkts_sorted = sorted(pkts, key=lambda x: x['ts'])
        total_bytes = sum(p.get('length') or 0 for p in pkts_sorted)
        flow_info = {
            'flow_key': key,
            'packets': len(pkts_sorted),
            'bytes': total_bytes,
            'start_ts': pkts_sorted[0]['ts'] if pkts_sorted else None,
            'end_ts': pkts_sorted[-1]['ts'] if pkts_sorted else None,
            'flowlets': [],
        }
        flowlets = split_flowlets(pkts_sorted, threshold=threshold)
        # summarize flowlets
        for idx, f in enumerate(flowlets, start=1):
            flowlet_summary = {
                'id': idx,
                'start_ts': f['start_ts'],
                'end_ts': f['end_ts'],
                'packets': f['packets'],
                'bytes': f['bytes'],
            }
            flow_info['flowlets'].append(flowlet_summary)

        out['flows'].append(flow_info)

    return out


def main(argv=None):
    p = argparse.ArgumentParser(description='Parse tcpdump-style text into flows and flowlets')
    p.add_argument('input', help='input capture text file')
    p.add_argument('--threshold', '-t', type=float, default=0.1, help='flowlet gap threshold in seconds (default: 0.1s)')
    p.add_argument('--bidirectional', '-b', action='store_true', help='treat flows as bidirectional (fold directions)')
    p.add_argument('--output', '-o', help='write JSON summary to this file')
    p.add_argument('--sample', action='store_true', help='print a small human-readable sample summary')
    args = p.parse_args(argv)

    packets = parse_capture_text(args.input)
    flows = group_packets_into_flows(packets, bidirectional=args.bidirectional)
    summary = build_summary(flows, threshold=args.threshold, bidirectional=args.bidirectional)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as fh:
            json.dump(summary, fh, indent=2)
        print(f'Wrote JSON summary to {args.output}')
    if args.sample or not args.output:
        # print brief summary
        print(f"Flows: {summary['flows_count']}, threshold={summary['threshold']}s, bidir={summary['bidirectional']}")
        # print top 10 flows by bytes
        flows_sorted = sorted(summary['flows'], key=lambda x: x['bytes'], reverse=True)
        for f in flows_sorted[:10]:
            key = f['flow_key']
            print(f"Flow {key}: pkts={f['packets']}, bytes={f['bytes']}, flowlets={len(f['flowlets'])}, start={f['start_ts']}, end={f['end_ts']}")


if __name__ == '__main__':
    main()
