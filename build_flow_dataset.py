#!/usr/bin/env python3
"""build_flow_dataset.py

Walk the captures directory, parse every tcpdump text capture, and emit a
single JSON dataset containing labeled flows and flowlets. Files that live in a
directory whose name starts with "all" are tagged as general (non-LLM) traffic;
everything else is labeled as LLM traffic.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Dict, List, Tuple

import parse_flowlets as pf  # reuse parsing helpers


def classify_capture(path: Path, root: Path) -> str:
    rel_parts = path.relative_to(root).parts
    for part in rel_parts:
        if part.lower().startswith('all'):
            return 'non_llm'
    return 'llm'


def find_capture_files(root: Path, pattern: str) -> List[Path]:
    if not root.exists():
        raise FileNotFoundError(f'Captures directory {root} does not exist')
    return sorted(p for p in root.rglob(pattern) if p.is_file())


def summarize_flows(packets: List[Dict], bidirectional: bool, threshold: float) -> List[Dict]:
    flows = pf.group_packets_into_flows(packets, bidirectional=bidirectional)
    summaries = []
    for key, pkts in flows.items():
        pkts_sorted = sorted(pkts, key=lambda x: x['ts'])
        flowlets = pf.split_flowlets(pkts_sorted, threshold=threshold)
        summaries.append(
            {
                'flow_key': key,
                'packets': len(pkts_sorted),
                'bytes': sum(p.get('length') or 0 for p in pkts_sorted),
                'start_ts': pkts_sorted[0]['ts'] if pkts_sorted else None,
                'end_ts': pkts_sorted[-1]['ts'] if pkts_sorted else None,
                'flowlets': [
                    {
                        'id': idx,
                        'start_ts': fl['start_ts'],
                        'end_ts': fl['end_ts'],
                        'packets': fl['packets'],
                        'bytes': fl['bytes'],
                    }
                    for idx, fl in enumerate(flowlets, start=1)
                ],
            }
        )
    return summaries


def build_dataset(root: Path, pattern: str, bidirectional: bool, threshold: float) -> Dict:
    files = find_capture_files(root, pattern)
    dataset = {
        'generated_at': dt.datetime.utcnow().isoformat() + 'Z',
        'captures_root': str(root),
        'file_pattern': pattern,
        'threshold': threshold,
        'bidirectional': bidirectional,
        'captures': [],
        'flows': [],
        'flowlets': [],
    }

    for path in files:
        traffic_class = classify_capture(path, root)
        packets = pf.parse_capture_text(path)
        for pkt in packets:
            pkt['traffic_class'] = traffic_class
            pkt['source_file'] = str(path)

        flow_summaries = summarize_flows(packets, bidirectional, threshold)
        dataset['captures'].append(
            {
                'file': str(path),
                'traffic_class': traffic_class,
                'flows_count': len(flow_summaries),
                'packets': len(packets),
            }
        )
        for flow in flow_summaries:
            flow['traffic_class'] = traffic_class
            flow['source_file'] = str(path)
            for flowlet in flow['flowlets']:
                flowlet['traffic_class'] = traffic_class
                flowlet['source_file'] = str(path)
            dataset['flows'].append(flow)
            dataset['flowlets'].extend(flow['flowlets'])

    dataset['files_processed'] = len(files)
    dataset['total_flows'] = len(dataset['flows'])
    dataset['total_flowlets'] = len(dataset['flowlets'])
    return dataset


def main():
    parser = argparse.ArgumentParser(description='Build a labeled flow/flowlet dataset from capture text files.')
    parser.add_argument('--captures-dir', default='captures', help='Root directory containing tcpdump text files (default: captures)')
    parser.add_argument('--pattern', default='*.txt', help='Glob pattern (relative) for capture files (default: *.txt)')
    parser.add_argument('--threshold', type=float, default=0.1, help='Flowlet gap threshold in seconds (default: 0.1)')
    parser.add_argument('--bidirectional', action='store_true', help='Treat flows as bidirectional when grouping packets')
    parser.add_argument('--output', '-o', default='flow_dataset.json', help='Output JSON file (default: flow_dataset.json)')
    parser.add_argument('--sample', action='store_true', help='Print summary stats to stdout')
    args = parser.parse_args()

    dataset = build_dataset(Path(args.captures_dir), args.pattern, args.bidirectional, args.threshold)

    with open(args.output, 'w', encoding='utf-8') as fh:
        json.dump(dataset, fh, indent=2)
    if args.sample:
        llm_flows = sum(1 for flow in dataset['flows'] if flow['traffic_class'] == 'llm')
        non_flows = dataset['total_flows'] - llm_flows
        print(
            f"Files: {dataset['files_processed']}, flows={dataset['total_flows']} (LLM={llm_flows}, non-LLM={non_flows}), "
            f"flowlets={dataset['total_flowlets']}"
        )
        top_flows = sorted(dataset['flows'], key=lambda f: f['bytes'], reverse=True)[:10]
        for flow in top_flows:
            print(
                f"[{flow['traffic_class']}] {flow['flow_key']} bytes={flow['bytes']} flowlets={len(flow['flowlets'])} "
                f"file={flow['source_file']}"
            )


if __name__ == '__main__':
    main()
